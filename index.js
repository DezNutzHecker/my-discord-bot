'use strict';

const {
  Client, GatewayIntentBits, REST, Routes,
  SlashCommandBuilder, AttachmentBuilder, EmbedBuilder,
  Events, MessageFlags,
} = require('discord.js');
const crypto = require('node:crypto');
require('dotenv').config();

let fengari = null;
try { fengari = require('fengari'); } catch { console.warn('fengari not installed — /sandbox disabled'); }

const { DISCORD_TOKEN, CLIENT_ID, GUILD_ID } = process.env;
if (!DISCORD_TOKEN || !CLIENT_ID) {
  console.error('Missing DISCORD_TOKEN or CLIENT_ID in .env');
  process.exit(1);
}

const MAX_BYTES = 8014 * 1024;
const MAX_INLINE = 1900;
const MAX_OUTPUT_FILE = 24 * 1024 * 1024;
const STAGE_TIMEOUT_MS = 60_000;
const SANDBOX_TIMEOUT_MS = 10_000;
const CACHE_MAX = 200;
const CACHE_TTL_MS = 30 * 60 * 1000;

// ==================== CACHE ====================

class LRU {
  constructor(max, ttl) { this.max = max; this.ttl = ttl; this.map = new Map(); }
  _expired(e) { return Date.now() - e.t > this.ttl; }
  get(k) {
    const e = this.map.get(k);
    if (!e) return null;
    if (this._expired(e)) { this.map.delete(k); return null; }
    this.map.delete(k); this.map.set(k, e);
    return e.v;
  }
  set(k, v) {
    if (this.map.has(k)) this.map.delete(k);
    this.map.set(k, { v, t: Date.now() });
    while (this.map.size > this.max) this.map.delete(this.map.keys().next().value);
  }
}
const cache = new LRU(CACHE_MAX, CACHE_TTL_MS);
const hashOf = s => crypto.createHash('sha256').update(s).digest('hex');

// ==================== HELPERS ====================

function escapeLua(s) {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    .replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t')
    .replace(/[\x00-\x1f\x7f]/g, c => '\\' + c.charCodeAt(0));
}
function escRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function walkStrings(code, fn) {
  let out = '', i = 0, inStr = null, buf = '', q = '';
  while (i < code.length) {
    const c = code[i];
    if (inStr) {
      if (c === '\\' && i + 1 < code.length) { buf += c + code[i+1]; i += 2; continue; }
      if (c === inStr) { out += q + fn(buf) + q; inStr = null; buf = ''; q = ''; i++; continue; }
      buf += c; i++; continue;
    }
    if (c === '"' || c === "'") { inStr = c; q = c; i++; continue; }
    out += c; i++;
  }
  if (inStr) out += q + buf;
  return out;
}

function stripComments(code) {
  code = code.replace(/--\[(=*)\[[\s\S]*?\]\1\]/g, '');
  let out = '', i = 0, inStr = null;
  while (i < code.length) {
    const c = code[i], n = code[i+1];
    if (!inStr) {
      if (c === '-' && n === '-') { while (i < code.length && code[i] !== '\n') i++; continue; }
      if (c === '"' || c === "'") { inStr = c; out += c; i++; continue; }
      out += c; i++;
    } else {
      if (c === '\\' && i+1 < code.length) { out += c + code[i+1]; i += 2; continue; }
      if (c === inStr) inStr = null;
      out += c; i++;
    }
  }
  return out;
}

function printableScore(s) {
  if (!s.length) return 0;
  let p = 0;
  for (const c of s) {
    const x = c.charCodeAt(0);
    if (x === 9 || x === 10 || x === 13 || (x >= 32 && x <= 126)) p++;
  }
  return p / s.length;
}

function looksLikeLua(s) {
  const kw = /\b(local|function|end|if|then|else|return|for|while|do|repeat|until|elseif)\b/g;
  const matches = s.match(kw);
  return matches && matches.length >= 2;
}

function withTimeout(fn, ms, fallback) {
  const start = Date.now();
  try {
    const r = fn();
    if (Date.now() - start > ms) return fallback;
    return r;
  } catch { return fallback; }
}

// ==================== STRING DECODERS ====================

function decodeHex(code) {
  return walkStrings(code, b =>
    b.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) =>
      escapeLua(String.fromCharCode(parseInt(h, 16)))));
}

function decodeDecimal(code) {
  return walkStrings(code, b =>
    b.replace(/\\(\d{1,3})/g, (m, d) => {
      const n = parseInt(d, 10);
      if (n > 255) return m;
      return escapeLua(String.fromCharCode(n));
    }));
}

function decodeUnicode(code) {
  return walkStrings(code, b =>
    b.replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, h) =>
      escapeLua(String.fromCodePoint(parseInt(h, 16)))));
}

function decodeStringChar(code) {
  let prev;
  do {
    prev = code;
    code = code.replace(/string\.char\s*\(([^()]+)\)/g, (m, args) => {
      const parts = args.split(',').map(s => s.trim());
      if (!parts.every(p => /^-?\d+$/.test(p))) return m;
      try {
        const chars = parts.map(p => {
          const n = parseInt(p, 10);
          if (n < 0 || n > 255) throw new Error();
          return String.fromCharCode(n);
        });
        return `"${escapeLua(chars.join(''))}"`;
      } catch { return m; }
    });
  } while (code !== prev);
  return code;
}

function decodeBase64Strings(code) {
  let count = 0;
  const result = walkStrings(code, b => {
    if (b.length < 16 || b.length % 4 !== 0) return b;
    if (!/^[A-Za-z0-9+/]+=*$/.test(b)) return b;
    try {
      const decoded = Buffer.from(b, 'base64').toString('utf-8');
      if (printableScore(decoded) > 0.9 && decoded.length > 4) {
        count++;
        return escapeLua(decoded);
      }
    } catch {}
    return b;
  });
  return { code: result, count };
}

function bruteXorStrings(code) {
  let count = 0;
  const result = walkStrings(code, b => {
    if (b.length < 16 || b.length > 50000) return b;
    if (printableScore(b) > 0.9 && looksLikeLua(b)) return b;
    let best = null;
    // 1-byte keys
    for (let k = 1; k < 256; k++) {
      let decoded = '';
      for (let i = 0; i < b.length; i++) decoded += String.fromCharCode(b.charCodeAt(i) ^ k);
      const score = printableScore(decoded);
      if (score > 0.95 && /[a-zA-Z]{3,}/.test(decoded)) {
        if (!best || score > best.score) best = { decoded, score };
      }
    }
    // 2-byte keys (sample of common ones)
    if (!best && b.length > 50) {
      for (let k1 = 1; k1 < 256; k1 += 17) {
        for (let k2 = 1; k2 < 256; k2 += 17) {
          let decoded = '';
          for (let i = 0; i < b.length; i++) {
            const k = (i % 2 === 0) ? k1 : k2;
            decoded += String.fromCharCode(b.charCodeAt(i) ^ k);
          }
          const score = printableScore(decoded);
          if (score > 0.97 && looksLikeLua(decoded)) {
            if (!best || score > best.score) best = { decoded, score };
          }
        }
      }
    }
    if (best) { count++; return escapeLua(best.decoded); }
    return b;
  });
  return { code: result, count };
}

function bruteCaesarStrings(code) {
  let count = 0;
  const result = walkStrings(code, b => {
    if (b.length < 16 || b.length > 10000) return b;
    if (printableScore(b) > 0.9) return b;
    let best = null;
    for (let off = 1; off < 128; off++) {
      let decoded = '';
      for (let i = 0; i < b.length; i++) {
        decoded += String.fromCharCode((b.charCodeAt(i) - off + 256) % 256);
      }
      const score = printableScore(decoded);
      if (score > 0.97 && /[a-zA-Z]{3,}/.test(decoded)) {
        if (!best || score > best.score) best = { decoded, score };
      }
    }
    if (best) { count++; return escapeLua(best.decoded); }
    return b;
  });
  return { code: result, count };
}

function tryReverseStrings(code) {
  let count = 0;
  const result = walkStrings(code, b => {
    if (b.length < 16) return b;
    if (printableScore(b) > 0.95 && looksLikeLua(b)) return b;
    const reversed = [...b].reverse().join('');
    if (printableScore(reversed) > 0.97 && looksLikeLua(reversed)) {
      count++;
      return escapeLua(reversed);
    }
    return b;
  });
  return { code: result, count };
}

// ==================== FOLDING ====================

function foldConcat(code) {
  let prev;
  do {
    prev = code;
    code = code.replace(/"((?:\\.|[^"\\])*)"\s*\.\.\s*"((?:\\.|[^"\\])*)"/g,
      (_, a, b) => `"${a}${b}"`);
  } while (code !== prev);
  return code;
}

function foldArithmetic(code) {
  let prev;
  do {
    prev = code;
    code = code.replace(/\(\s*(-?\d+(?:\.\d+)?)\s*([+\-*/%])\s*(-?\d+(?:\.\d+)?)\s*\)/g,
      (m, a, op, b) => {
        const x = parseFloat(a), y = parseFloat(b); let r;
        switch (op) {
          case '+': r = x + y; break;
          case '-': r = x - y; break;
          case '*': r = x * y; break;
          case '/': if (y === 0) return m; r = x / y; break;
          case '%': if (y === 0) return m; r = ((x % y) + y) % y; break;
        }
        if (!isFinite(r)) return m;
        return Number.isInteger(r) ? String(r) : r.toFixed(6).replace(/\.?0+$/, '');
      });
  } while (code !== prev);
  return code;
}

function foldBit32(code) {
  const ops = {
    bxor: (...a) => a.reduce((x, y) => (x ^ y) >>> 0),
    band: (...a) => a.reduce((x, y) => (x & y) >>> 0),
    bor:  (...a) => a.reduce((x, y) => (x | y) >>> 0),
    bnot: a => (~a) >>> 0,
    lshift: (a, b) => (a << b) >>> 0,
    rshift: (a, b) => (a >>> b),
    arshift: (a, b) => (a >> b) >>> 0,
  };
  let prev;
  do {
    prev = code;
    code = code.replace(/bit32\.(\w+)\s*\(([^()]+)\)/g, (m, op, args) => {
      const fn = ops[op]; if (!fn) return m;
      const parts = args.split(',').map(s => s.trim());
      if (!parts.every(p => /^-?\d+$/.test(p))) return m;
      try { return String(fn(...parts.map(p => parseInt(p, 10) >>> 0))); }
      catch { return m; }
    });
  } while (code !== prev);
  return code;
}

// ==================== STRUCTURAL ====================

function splitTopLevelCommas(s) {
  const out = []; let depth = 0, buf = '', inStr = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (c === '\\') { buf += c + (s[i+1] || ''); i++; continue; }
      if (c === inStr) inStr = null;
      buf += c; continue;
    }
    if (c === '"' || c === "'") { inStr = c; buf += c; continue; }
    if ('{(['.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    if (c === ',' && depth === 0) { out.push(buf); buf = ''; continue; }
    buf += c;
  }
  if (buf.trim()) out.push(buf);
  return out;
}

function resolveConstantTables(code) {
  const tables = new Map();
  const re = /local\s+(\w+)\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const name = m[1];
    const items = splitTopLevelCommas(m[2]).map(s => s.trim()).filter(Boolean);
    if (items.length < 2) continue;
    const lits = []; let ok = true;
    for (const it of items) {
      const sm = it.match(/^(["'])((?:\\.|(?!\1)[^\\])*)\1$/);
      const nm = it.match(/^-?\d+(?:\.\d+)?$/);
      const bm = /^(true|false|nil)$/.exec(it);
      if (sm) lits.push({ k: 's', v: sm[2], q: sm[1] });
      else if (nm) lits.push({ k: 'n', v: it });
      else if (bm) lits.push({ k: 'l', v: bm[1] });
      else { ok = false; break; }
    }
    if (ok && lits.length >= 2) tables.set(name, lits);
  }
  for (const [name, lits] of tables) {
    const idxRe = new RegExp(`\\b${escRe(name)}\\s*\\[\\s*(\\d+)\\s*\\]`, 'g');
    code = code.replace(idxRe, (full, idx) => {
      const i = parseInt(idx, 10) - 1;
      if (i < 0 || i >= lits.length) return full;
      const l = lits[i];
      return l.k === 's' ? `${l.q}${l.v}${l.q}` : l.v;
    });
  }
  return code;
}

function inlineTrivialFunctions(code) {
  const re = /local\s+(\w+)\s*=\s*function\s*\(\s*\)\s*return\s+(["'][^"'\n]*["']|-?\d+(?:\.\d+)?)\s+end/g;
  const inlines = new Map();
  let m;
  while ((m = re.exec(code)) !== null) inlines.set(m[1], m[2]);
  for (const [name, val] of inlines) {
    const callRe = new RegExp(`\\b${escRe(name)}\\s*\\(\\s*\\)`, 'g');
    code = code.replace(callRe, val);
  }
  return code;
}

function unwrapLoadstrings(code, max = 12) {
  let layers = 0;
  for (let i = 0; i < max; i++) {
    const m = code.match(/load(?:string)?\s*\(\s*(["'])((?:\\.|(?!\1)[^\\])+)\1\s*\)\s*\(\s*\)/);
    if (!m) break;
    const inner = decodeUnicode(decodeHex(decodeDecimal(m[2])));
    if (inner === m[2] || inner.length < 5) break;
    code = code.replace(m[0], inner);
    layers++;
  }
  return { code, layers };
}

function renameUglyIdentifiers(code) {
  const seen = new Map();
  let counter = 0;
  const ugly = /\b(_0x[0-9a-fA-F]{4,}|_+[ilIO10]{4,}_*|[A-Z_]{12,})\b/g;
  let m;
  while ((m = ugly.exec(code)) !== null) {
    const name = m[1];
    if (!seen.has(name)) seen.set(name, `v${++counter}`);
  }
  const sorted = [...seen.keys()].sort((a, b) => b.length - a.length);
  for (const k of sorted) {
    code = code.replace(new RegExp(`\\b${escRe(k)}\\b`, 'g'), seen.get(k));
  }
  return { code, renamed: seen.size };
}

function removeDeadCode(code) {
  code = code.replace(/\bif\s+false\s+then\b[\s\S]*?\bend\b/g, '');
  code = code.replace(/\bwhile\s+false\s+do\b[\s\S]*?\bend\b/g, '');
  code = code.replace(/\bdo\s+end\b/g, '');
  return code.replace(/\n{3,}/g, '\n\n');
}

// ==================== BEAUTIFY ====================

function beautify(code) {
  const tokens = [];
  let i = 0, inStr = null, buf = '';
  while (i < code.length) {
    const c = code[i];
    if (inStr) {
      buf += c;
      if (c === '\\' && i+1 < code.length) { buf += code[i+1]; i += 2; continue; }
      if (c === inStr) { tokens.push({ s: true, v: buf }); buf = ''; inStr = null; }
      i++; continue;
    }
    if (c === '"' || c === "'") { if (buf) { tokens.push({ s: false, v: buf }); buf = ''; } inStr = c; buf = c; i++; continue; }
    buf += c; i++;
  }
  if (buf) t
