'use strict';

const {
  Client, GatewayIntentBits, REST, Routes,
  SlashCommandBuilder, AttachmentBuilder, EmbedBuilder,
  Events, MessageFlags,
} = require('discord.js');
const crypto = require('node:crypto');
require('dotenv').config();

let fengari = null;
try { fengari = require('fengari'); } catch { console.warn('fengari not installed - /sandbox disabled'); }

const { DISCORD_TOKEN, CLIENT_ID, GUILD_ID } = process.env;
if (!DISCORD_TOKEN || !CLIENT_ID) {
  console.error('Missing DISCORD_TOKEN or CLIENT_ID in .env');
  process.exit(1);
}

const MAX_BYTES = 8014 * 1024;
const MAX_INLINE = 1900;
const MAX_OUTPUT_FILE = 24 * 1024 * 1024;
const SANDBOX_TIMEOUT_MS = 6000_000;
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
    // Match string.char with only numeric args (skip nested expressions)
    code = code.replace(/string\.char\s*\(\s*((?:-?\d+\s*,\s*)*-?\d+)\s*\)/g, (m, args) => {
      const parts = args.split(',').map(s => s.trim());
      try {
        const chars = parts.map(p => {
          const n = parseInt(p, 10);
          if (isNaN(n) || n < 0 || n > 255) throw new Error();
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
    // Skip anything already printable - don't risk wrecking valid strings
    if (printableScore(b) > 0.85) return b;
    // Skip anything that has any printable letter sequence - likely valid plain text
    if (/[a-zA-Z]{4,}/.test(b) && printableScore(b) > 0.7) return b;
    let best = null;
    for (let k = 1; k < 256; k++) {
      let decoded = '';
      for (let i = 0; i < b.length; i++) decoded += String.fromCharCode(b.charCodeAt(i) ^ k);
      const score = printableScore(decoded);
      // Require both high printability AND Lua-like content
      if (score > 0.97 && looksLikeLua(decoded)) {
        if (!best || score > best.score) best = { decoded, score };
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
    if (printableScore(b) > 0.85) return b;
    if (/[a-zA-Z]{4,}/.test(b) && printableScore(b) > 0.7) return b;
    let best = null;
    for (let off = 1; off < 128; off++) {
      let decoded = '';
      for (let i = 0; i < b.length; i++) {
        decoded += String.fromCharCode((b.charCodeAt(i) - off + 256) % 256);
      }
      const score = printableScore(decoded);
      if (score > 0.97 && looksLikeLua(decoded)) {
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
    // Match loadstring("..." or loadstring(varname) followed by ()
    const stringArg = code.match(/load(?:string)?\s*\(\s*(["'])((?:\\.|(?!\1)[^\\])+)\1\s*\)\s*\(\s*\)/);
    if (stringArg) {
      const inner = decodeUnicode(decodeHex(decodeDecimal(stringArg[2])));
      if (inner === stringArg[2] || inner.length < 5) break;
      code = code.replace(stringArg[0], inner);
      layers++;
      continue;
    }
    // Match loadstring(variable)() — try to resolve the variable
    const varArg = code.match(/load(?:string)?\s*\(\s*(\w+)\s*\)\s*\(\s*\)/);
    if (varArg) {
      const varName = varArg[1];
      const defRe = new RegExp(`\\blocal\\s+${escRe(varName)}\\s*=\\s*(["'])((?:\\\\.|(?!\\1)[^\\\\])+)\\1`);
      const defMatch = code.match(defRe);
      if (defMatch) {
        const inner = decodeUnicode(decodeHex(decodeDecimal(defMatch[2])));
        if (inner.length > 5) {
          code = code.replace(varArg[0], inner);
          layers++;
          continue;
        }
      }
    }
    break;
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
    // Long-bracket strings [[ ... ]]
    if (c === '[' && code[i+1] === '[') {
      if (buf) { tokens.push({ s: false, v: buf }); buf = ''; }
      const end = code.indexOf(']]', i + 2);
      if (end === -1) { buf += code.slice(i); i = code.length; continue; }
      tokens.push({ s: true, v: code.slice(i, end + 2) });
      i = end + 2; continue;
    }
    if (c === '"' || c === "'") { if (buf) { tokens.push({ s: false, v: buf }); buf = ''; } inStr = c; buf = c; i++; continue; }
    buf += c; i++;
  }
  if (buf) tokens.push({ s: !!inStr, v: buf });

  let joined = '';
  for (const t of tokens) {
    if (t.s) joined += t.v;
    else {
      let v = t.v;
      // Only split on `;` if it's clearly a statement separator (not in a for-loop header etc)
      v = v.replace(/;\s*(?=[a-zA-Z_])/g, '\n');
      // Add newline AFTER then/do only if followed by non-whitespace, non-newline
      v = v.replace(/\b(then|do)\b(?=[ \t]+[a-zA-Z_])/g, '$1\n');
      // Add newline BEFORE end/else/elseif/until when preceded by content
      v = v.replace(/([^\s])\s+\b(end|else|elseif|until)\b/g, '$1\n$2');
      joined += v;
    }
  }

  const lines = joined.split('\n').map(l => l.trim()).filter(Boolean);
  const result = [];
  let indent = 0;
  for (const l of lines) {
    if (/^(end\b|else\b|elseif\b|until\b)/.test(l)) indent = Math.max(0, indent - 1);
    result.push('  '.repeat(indent) + l);
    if (/\b(then|do|repeat|else)\s*$/.test(l)) indent++;
    if (/\bfunction\b[^)]*\)\s*$/.test(l)) indent++;
    if (/^(else|elseif)\b/.test(l)) indent++;
  }
  return result.join('\n') + '\n';
}

  const lines = joined.split('\n').map(l => l.trim()).filter(Boolean);
  const result = [];
  let indent = 0;
  for (const l of lines) {
    if (/^(end|else|elseif|until)\b/.test(l)) indent = Math.max(0, indent - 1);
    result.push('  '.repeat(indent) + l);
    if (/\b(then|do|function[^)]*\)|repeat|else)\s*$/.test(l)) indent++;
    if (/^(else|elseif)\b/.test(l)) indent++;
  }
  return result.join('\n') + '\n';
}
// ==================== WEAREDEVS UNPACKER ====================

function isWeAreDevs(code) {
  return /wearedevs\.net\/obfuscator/i.test(code) ||
         /--\[\[\s*v\d+\.\d+\.\d+\s+https?:\/\/wearedevs/i.test(code);
}

function extractWadConstantTable(code) {
  // Find `local o = { ... }` near the start
  const m = code.match(/local\s+(\w+)\s*=\s*\{([\s\S]*?)\}\s*(?:[,;]|local|for|while|repeat|return|end)/);
  if (!m) return null;
  const name = m[1];
  const body = m[2];

  // WAD strings are separated by `;` or `,`
  // Each string is "\NNN\NNN\NNN..." form
  const strings = [];
  const re = /"((?:\\\d{1,3}|\\x[0-9a-fA-F]{2}|\\.|[^"\\])*)"/g;
  let sm;
  while ((sm = re.exec(body)) !== null) {
    strings.push(decodeAllEscapesInString(sm[1]));
  }
  return { name, strings, raw: body };
}

function decodeAllEscapesInString(s) {
  let out = '';
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '\\' && i + 1 < s.length) {
      const n = s[i+1];
      // \NNN decimal
      if (/\d/.test(n)) {
        let num = '';
        let j = i + 1;
        while (j < s.length && num.length < 3 && /\d/.test(s[j])) {
          num += s[j]; j++;
        }
        const code = parseInt(num, 10);
        if (code <= 255) { out += String.fromCharCode(code); i = j; continue; }
      }
      // \xNN hex
      if (n === 'x' && i + 3 < s.length) {
        const h = s.slice(i+2, i+4);
        if (/^[0-9a-fA-F]{2}$/.test(h)) {
          out += String.fromCharCode(parseInt(h, 16));
          i += 4; continue;
        }
      }
      // Standard escapes
      if (n === 'n') { out += '\n'; i += 2; continue; }
      if (n === 't') { out += '\t'; i += 2; continue; }
      if (n === 'r') { out += '\r'; i += 2; continue; }
      if (n === '\\' || n === '"' || n === "'") { out += n; i += 2; continue; }
      out += n; i += 2; continue;
    }
    out += c; i++;
  }
  return out;
}

function tryBase64Decode(s) {
  // Standard b64 first
  if (/^[A-Za-z0-9+/]+=*$/.test(s) && s.length % 4 === 0) {
    try {
      const decoded = Buffer.from(s, 'base64').toString('utf-8');
      if (printableScore(decoded) > 0.85) return decoded;
    } catch {}
  }
  return null;
}

function unpackWeAreDevs(code) {
  const result = {
    detected: false,
    decoded: null,
    strings: [],
    joinedPayload: null,
    error: null,
    stats: { totalStrings: 0, base64Decoded: 0, payloadSize: 0 },
  };

  if (!isWeAreDevs(code)) {
    result.error = 'Not a WeAreDevs script (no v1.0.0 header found)';
    return result;
  }
  result.detected = true;

  const table = extractWadConstantTable(code);
  if (!table) {
    result.error = 'Could not find constant table';
    return result;
  }

  result.stats.totalStrings = table.strings.length;
  result.strings = table.strings;

  // Try base64 on each string
  let b64Count = 0;
  const b64Decoded = [];
  for (const s of table.strings) {
    const dec = tryBase64Decode(s);
    if (dec) { b64Decoded.push(dec); b64Count++; }
    else b64Decoded.push(null);
  }
  result.stats.base64Decoded = b64Count;

  // WAD typically concatenates all strings into one payload
  // Strategy 1: join all decoded strings if most look like b64
  // Strategy 2: join raw strings
  // Strategy 3: alternate strategies based on what looks like Lua

  const candidates = [];

  // Joined raw (most common WAD pattern - the table IS the payload chunks)
  candidates.push({ name: 'joined-raw', code: table.strings.join('') });

  // Joined base64-decoded (when each entry is a b64 chunk)
  if (b64Count > table.strings.length * 0.5) {
    candidates.push({
      name: 'joined-base64',
      code: b64Decoded.filter(x => x).join(''),
    });
  }

  // Reverse-join (some WAD variants reverse the order)
  candidates.push({ name: 'reversed-raw', code: [...table.strings].reverse().join('') });

  // Pick the candidate that looks most like Lua
  let best = null;
  for (const c of candidates) {
    if (!c.code || c.code.length < 20) continue;
    const luaScore = (c.code.match(/\b(local|function|end|return|if|then|else|for|while|do)\b/g) || []).length;
    if (!best || luaScore > best.luaScore) {
      best = { ...c, luaScore };
    }
  }

  if (best && best.luaScore >= 3) {
    result.joinedPayload = best.code;
    result.stats.payloadSize = best.code.length;
    result.decoded = beautify(stripComments(best.code));
  } else {
    // Couldn't reconstruct - dump strings for manual analysis
    result.error = 'Could not reconstruct a Lua payload from table strings. See raw strings below.';
  }

  return result;
}
// ==================== FINGERPRINTING ====================

function detectObfuscator(code) {
  const hints = [];
  if (/Luraph|LPH_|lph_/i.test(code)) hints.push('Luraph');
  if (/Moonsec|MoonSec/i.test(code)) hints.push('Moonsec');
  if (/Ironbrew|IronBrew/i.test(code)) hints.push('IronBrew');
  if (/Prometheus/i.test(code)) hints.push('Prometheus');
  if (/Wynfuscate/i.test(code)) hints.push('Wynfuscate');
  if (/WeAreDevs/i.test(code)) hints.push('WeAreDevs');
  if (/SynapseXen|Synapse\s*Xen/i.test(code)) hints.push('Synapse Xen');
  if (/Hercules/i.test(code)) hints.push('Hercules');
  if (/luaobfuscator\.com/i.test(code)) hints.push('LuaObfuscator.com');
  if ((code.match(/\\x[0-9a-f]{2}/gi) || []).length > 20) hints.push('hex-encoded strings');
  if ((code.match(/string\.char\s*\(\s*\d+/g) || []).length > 5) hints.push('string.char encoding');
  if (/load(?:string)?\s*\(\s*["']/.test(code)) hints.push('loadstring wrapper');
  if ((code.match(/bit32\.(bxor|band|bor)/g) || []).length > 5) hints.push('bitwise obfuscation');
  if (/while\s+true\s+do[\s\S]{0,200}if\s+\w+\s*==\s*\d+\s+then/.test(code)) hints.push('VM-style dispatcher');
  if ((code.match(/_0x[0-9a-f]{4,}/gi) || []).length > 10) hints.push('hex-mangled identifiers');
  return hints;
}

// ==================== SANDBOX ====================

function sandboxExecute(code) {
  if (!fengari) return { available: false, captured: [], error: 'fengari not installed' };

  const captured = [];
  const { lua, lauxlib, lualib, to_luastring } = fengari;
  const L = lauxlib.luaL_newstate();
  lualib.luaL_openlibs(L);

  // Hook loadstring/load: capture payload AND return a fake function so chained () doesn't blow up
  const captureLoad = (L) => {
    if (lua.lua_isstring(L, 1)) {
      const s = lua.lua_tojsstring(L, 1);
      if (s && s.length > 5) captured.push({ type: 'load', value: s });
    }
    lua.lua_pushjsfunction(L, (L2) => 0);
    return 1;
  };

  lua.lua_pushjsfunction(L, captureLoad); lua.lua_setglobal(L, to_luastring('loadstring'));
  lua.lua_pushjsfunction(L, captureLoad); lua.lua_setglobal(L, to_luastring('load'));

  const block = ['os', 'io', 'require', 'dofile', 'loadfile', 'package'];
  for (const name of block) {
    lua.lua_pushnil(L); lua.lua_setglobal(L, to_luastring(name));
  }

  lua.lua_pushjsfunction(L, (L) => {
    const n = lua.lua_gettop(L);
    const parts = [];
    for (let i = 1; i <= n; i++) {
      if (lua.lua_isstring(L, i)) parts.push(lua.lua_tojsstring(L, i));
      else parts.push(String(lua.lua_tonumber(L, i)));
    }
    captured.push({ type: 'print', value: parts.join('\t') });
    return 0;
  });
  lua.lua_setglobal(L, to_luastring('print'));

  const fakeGame = `
    local mt = {__index = function(t,k) return setmetatable({}, getmetatable(t)) end,
                __call = function(t, ...) return setmetatable({}, getmetatable(t)) end,
                __newindex = function(t,k,v) end}
    game = setmetatable({}, mt)
    workspace = setmetatable({}, mt)
    script = setmetatable({}, mt)
    wait = function() end
    spawn = function(f) end
    delay = function(t,f) end
    tick = function() return 0 end
    Instance = setmetatable({new = function() return setmetatable({}, mt) end}, mt)
  `;
  lauxlib.luaL_dostring(L, to_luastring(fakeGame));

  const start = Date.now();
  lua.lua_sethook(L, () => {
    if (Date.now() - start > SANDBOX_TIMEOUT_MS) {
      lauxlib.luaL_error(L, to_luastring('sandbox timeout'));
    }
  }, lua.LUA_MASKCOUNT, 1000000);

  try {
    const status = lauxlib.luaL_dostring(L, to_luastring(code));
    if (status !== lua.LUA_OK) {
      const err = lua.lua_tojsstring(L, -1) || 'unknown error';
      return { available: true, captured, error: err };
    }
    return { available: true, captured, error: null };
  } catch (e) {
    return { available: true, captured, error: e.message };
  }
}

  lua.lua_pushjsfunction(L, captureLoad); lua.lua_setglobal(L, to_luastring('loadstring'));
  lua.lua_pushjsfunction(L, captureLoad); lua.lua_setglobal(L, to_luastring('load'));

  // Block dangerous stuff
  const block = ['os', 'io', 'require', 'dofile', 'loadfile', 'package'];
  for (const name of block) {
    lua.lua_pushnil(L); lua.lua_setglobal(L, to_luastring(name));
  }

  // Capture print
  lua.lua_pushjsfunction(L, (L) => {
    const n = lua.lua_gettop(L);
    const parts = [];
    for (let i = 1; i <= n; i++) {
      if (lua.lua_isstring(L, i)) parts.push(lua.lua_tojsstring(L, i));
      else parts.push(String(lua.lua_tonumber(L, i)));
    }
    captured.push({ type: 'print', value: parts.join('\t') });
    return 0;
  });
  lua.lua_setglobal(L, to_luastring('print'));

  // Fake game env for Roblox scripts
  const fakeGame = `
    local mt = {__index = function(t,k) return setmetatable({}, getmetatable(t)) end,
                __call = function(t, ...) return setmetatable({}, getmetatable(t)) end,
                __newindex = function(t,k,v) end}
    game = setmetatable({}, mt)
    workspace = setmetatable({}, mt)
    script = setmetatable({}, mt)
    wait = function() end
    spawn = function(f) end
    delay = function(t,f) end
    tick = function() return 0 end
    Instance = setmetatable({new = function() return setmetatable({}, mt) end}, mt)
  `;
  lauxlib.luaL_dostring(L, to_luastring(fakeGame));

  // Time-limit via instruction hook
  const start = Date.now();
  lua.lua_sethook(L, () => {
    if (Date.now() - start > SANDBOX_TIMEOUT_MS) {
      lauxlib.luaL_error(L, to_luastring('sandbox timeout'));
    }
  }, lua.LUA_MASKCOUNT, 10000);

  try {
    const status = lauxlib.luaL_dostring(L, to_luastring(code));
    if (status !== lua.LUA_OK) {
      const err = lua.lua_tojsstring(L, -1) || 'unknown error';
      return { available: true, captured, error: err };
    }
    return { available: true, captured, error: null };
  } catch (e) {
    return { available: true, captured, error: e.message };
  }
}
// ==================== PIPELINE ====================

function decodeFull(code) {
  const stats = {
    originalSize: code.length, passes: 0, layers: 0,
    xorDecoded: 0, caesarDecoded: 0, base64Decoded: 0,
    reversedDecoded: 0, renamed: 0,
  };

  code = stripComments(code);

  let prev;
  do {
    prev = code;
    code = decodeHex(code);
    code = decodeDecimal(code);
    code = decodeUnicode(code);
    code = decodeStringChar(code);

    const b64 = decodeBase64Strings(code); code = b64.code; stats.base64Decoded += b64.count;

    code = foldConcat(code);
    code = foldArithmetic(code);
    code = foldBit32(code);
    code = resolveConstantTables(code);
    code = inlineTrivialFunctions(code);

    const unwrap = unwrapLoadstrings(code);
    code = unwrap.code; stats.layers += unwrap.layers;

    stats.passes++;
  } while (code !== prev && stats.passes < 12);

  const xorResult = bruteXorStrings(code);
  code = xorResult.code; stats.xorDecoded = xorResult.count;

  const caesarResult = bruteCaesarStrings(code);
  code = caesarResult.code; stats.caesarDecoded = caesarResult.count;

  const revResult = tryReverseStrings(code);
  code = revResult.code; stats.reversedDecoded = revResult.count;

  // One more sweep after brute decoders
  code = foldConcat(code);
  code = resolveConstantTables(code);
  const unwrap2 = unwrapLoadstrings(code);
  code = unwrap2.code; stats.layers += unwrap2.layers;

 function renameUglyIdentifiers(code) {
  // First, find all existing identifiers so we don't collide
  const existing = new Set();
  const idRe = /\b([a-zA-Z_]\w*)\b/g;
  let im;
  while ((im = idRe.exec(code)) !== null) existing.add(im[1]);

  const seen = new Map();
  let counter = 0;
  const ugly = /\b(_0x[0-9a-fA-F]{4,}|_+[ilIO10]{4,}_*|[A-Z_]{12,})\b/g;
  let m;
  while ((m = ugly.exec(code)) !== null) {
    const name = m[1];
    if (LUA_KEYWORDS && LUA_KEYWORDS.has(name)) continue;
    if (!seen.has(name)) {
      let candidate;
      do { candidate = `v${++counter}`; } while (existing.has(candidate));
      seen.set(name, candidate);
      existing.add(candidate);
    }
  }
  const sorted = [...seen.keys()].sort((a, b) => b.length - a.length);
  for (const k of sorted) {
    code = code.replace(new RegExp(`\\b${escRe(k)}\\b`, 'g'), seen.get(k));
  }
  return { code, renamed: seen.size };
}

// ==================== EXTRACTORS ====================

function extractStrings(code) {
  const found = [];
  walkStrings(code, b => { if (b.length >= 4) found.push(b); return b; });
  return [...new Set(found)];
}

function extractURLs(code) {
  const re = /https?:\/\/[^\s"'<>)]+/gi;
  return [...new Set(code.match(re) || [])];
}

function extractLoadstrings(code) {
  const out = [];
  const re = /load(?:string)?\s*\(\s*(["'])([\s\S]+?)\1\s*\)/g;
  let m;
  while ((m = re.exec(code)) !== null) out.push(m[2]);
  return out;
}

// ==================== SOURCE / OUTPUT ====================

async function getSource(interaction) {
  const code = interaction.options.getString('code');
  const file = interaction.options.getAttachment('file');
  const url = interaction.options.getString('url');

  if (file) {
    if (!/\.(lua|luau|txt)$/i.test(file.name || '')) return { error: 'File must be .lua, .luau, or .txt' };
    if (file.size > MAX_BYTES) return { error: `File too large (${(file.size/1024/1024).toFixed(2)} MB, max ${(MAX_BYTES/1024/1024).toFixed(2)} MB)` };
    try {
      const res = await fetch(file.url);
      if (!res.ok) return { error: `Fetch failed: ${res.status}` };
      return { code: await res.text() };
    } catch (e) { return { error: `Attachment fetch failed: ${e.message}` }; }
  }
  if (url) {
    if (!/^https?:\/\//i.test(url)) return { error: 'URL must start with http(s)://' };
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
      if (!res.ok) return { error: `URL fetch failed: ${res.status}` };
      const text = await res.text();
      if (Buffer.byteLength(text) > MAX_BYTES) return { error: 'Fetched content too large' };
      return { code: text };
    } catch (e) { return { error: `URL fetch failed: ${e.message}` }; }
  }
  if (code) return { code: code.replace(/\\n/g, '\n').replace(/\\t/g, '\t') };
  return { error: 'Provide code, file, or url' };
}

async function sendOutput(interaction, content, filename, extra = '') {
  if (content.length <= MAX_INLINE) {
    return interaction.editReply({ content: extra + '```lua\n' + content + '\n```' });
  }
  const buf = Buffer.from(content, 'utf-8');
  if (buf.length > MAX_OUTPUT_FILE) {
    return interaction.editReply({ content: extra + `Output too large to send (${(buf.length/1024/1024).toFixed(1)} MB, Discord cap is 25 MB).` });
  }
  return interaction.editReply({
    content: extra + `Output (${(buf.length/1024).toFixed(1)} KB)`,
    files: [new AttachmentBuilder(buf, { name: filename })],
  });
}

// ==================== COMMANDS ====================

const sourceOpts = b => b
  .addStringOption(o => o.setName('code').setDescription('Paste code').setRequired(false))
  .addAttachmentOption(o => o.setName('file').setDescription('Upload .lua/.luau/.txt').setRequired(false))
  .addStringOption(o => o.setName('url').setDescription('Raw URL').setRequired(false));

const commands = [
  new SlashCommandBuilder().setName('help').setDescription('Show command list'),
  sourceOpts(new SlashCommandBuilder().setName('beautify').setDescription('Clean up Lua formatting')),
  sourceOpts(new SlashCommandBuilder().setName('decode').setDescription('Full deobfuscation pipeline')),
  sourceOpts(new SlashCommandBuilder().setName('extract').setDescription('Extract strings, URLs, loadstrings')),
  sourceOpts(new SlashCommandBuilder().setName('detect').setDescription('Identify obfuscator used')),
  sourceOpts(new SlashCommandBuilder().setName('sandbox').setDescription('Run script in sandboxed Lua and dump payloads')),
  sourceOpts(new SlashCommandBuilder().setName('wad').setDescription('Unpack WeAreDevs obfuscator (fast, dedicated)')),
].map(c => c.toJSON());

async function registerCommands() {
  const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
  try {
    if (GUILD_ID) {
      console.log(`Registering ${commands.length} commands to guild ${GUILD_ID}...`);
      await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands });
    } else {
      console.log(`Registering ${commands.length} commands globally...`);
      await rest.put(Routes.applicationCommands(CLIENT_ID), { body: commands });
    }
    console.log('Commands registered.');
  } catch (e) { console.error('Registration failed:', e); process.exit(1); }
}

// ==================== BOT ====================

async function startBot() {
  const client = new Client({ intents: [GatewayIntentBits.Guilds] });

  client.once(Events.ClientReady, c => {
    console.log(`Online as ${c.user.tag}`);
    c.user.setActivity('/help', { type: 0 });
  });

  client.on(Events.InteractionCreate, async interaction => {
    if (!interaction.isChatInputCommand()) return;
    const cmd = interaction.commandName;

    try {
      if (cmd === 'help') {
        const embed = new EmbedBuilder()
          .setColor(0x00ff88)
          .setTitle('Commands')
          .addFields(
            { name: '/beautify', value: 'Clean up Lua formatting and indentation' },
            { name: '/decode', value: 'Full deobfuscation: escapes, base64, XOR, Caesar, constant tables, loadstring unwrap, identifier rename, dead code, beautify' },
            { name: '/extract', value: 'Pull strings, URLs, and loadstring payloads' },
            { name: '/detect', value: 'Identify which obfuscator was used' },
            { name: '/sandbox', value: 'Run the script in a sandboxed Lua VM and capture loadstring/print payloads' },
            { name: '/wad', value: 'Fast dedicated WeAreDevs unpacker (much faster than /sandbox for WAD scripts)' },
          )
          .setFooter({ text: `Max input: ${(MAX_BYTES/1024/1024).toFixed(2)} MB. Each command accepts code, file, or url.` });
        return interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral });
      }

      await interaction.deferReply();
      const src = await getSource(interaction);
      if (src.error) return interaction.editReply(src.error);

      const key = hashOf(cmd + ':' + src.code);
      const cached = cache.get(key);

      if (cmd === 'beautify') {
        let out;
        if (cached) out = cached;
        else { out = beautify(stripComments(src.code)); cache.set(key, out); }
        return sendOutput(interaction, out, 'beautified.lua', cached ? '(cached) ' : '');
      }

      if (cmd === 'decode') {
        let result;
        if (cached) result = cached;
        else {
          const start = Date.now();
          const r = decodeFull(src.code);
          r.stats.elapsedMs = Date.now() - start;
          result = r;
          cache.set(key, result);
        }
        const s = result.stats;
        const header =
          `-- Passes: ${s.passes} | Layers peeled: ${s.layers} | Strings: XOR=${s.xorDecoded} Caesar=${s.caesarDecoded} B64=${s.base64Decoded} Rev=${s.reversedDecoded} | Renamed: ${s.renamed}\n` +
          `-- Size: ${(s.originalSize/1024).toFixed(1)} KB -> ${(s.finalSize/1024).toFixed(1)} KB | ${cached ? '(cached)' : (s.elapsedMs + 'ms')}\n\n`;
        return sendOutput(interaction, header + result.code, 'decoded.lua');
      }

      if (cmd === 'extract') {
        let report;
        if (cached) report = cached;
        else {
          const stripped = stripComments(src.code);
          const strings = extractStrings(stripped).slice(0, 500);
          const urls = extractURLs(stripped);
          const loads = extractLoadstrings(stripped);
          report =
            `-- URLs (${urls.length}) --\n${urls.join('\n') || '(none)'}\n\n` +
            `-- Loadstring payloads (${loads.length}) --\n${loads.map((l,i) => `[${i+1}] ${l.slice(0,300)}`).join('\n') || '(none)'}\n\n` +
            `-- Strings (${strings.length}) --\n${strings.map(s => JSON.stringify(s)).join('\n')}`;
          cache.set(key, report);
        }
        return sendOutput(interaction, report, 'extract.txt');
      }

      if (cmd === 'detect') {
        const hints = detectObfuscator(src.code);
        const report = hints.length
          ? `Detected indicators:\n  - ${hints.join('\n  - ')}`
          : 'No known obfuscator signatures found.';
        return interaction.editReply('```\n' + report + '\n```');
      }

      if (cmd === 'sandbox') {
        const result = sandboxExecute(src.code);
        if (!result.available) return interaction.editReply('Sandbox unavailable: ' + result.error);
        const lines = [];
        lines.push(`-- Captured ${result.captured.length} event(s)`);
        if (result.error) lines.push(`-- Error: ${result.error}`);
        lines.push('');
        for (const e of result.captured) {
          lines.push(`-- [${e.type}] (${e.value.length} chars)`);
          lines.push(e.value);
          lines.push('');
        }
        return sendOutput(interaction, lines.join('\n'), 'sandbox.lua');
      }

      if (cmd === 'wad') {
        const result = unpackWeAreDevs(src.code);

        if (!result.detected) {
          return interaction.editReply('Not a WeAreDevs script. Try `/decode` for generic deobfuscation.');
        }

        const header =
          `-- WeAreDevs Unpacker\n` +
          `-- Strings in table: ${result.stats.totalStrings}\n` +
          `-- Base64-decodable: ${result.stats.base64Decoded}\n` +
          `-- Payload size: ${(result.stats.payloadSize/1024).toFixed(2)} KB\n` +
          (result.error ? `-- Note: ${result.error}\n` : '') +
          `\n`;

        if (result.decoded) {
          return sendOutput(interaction, header + result.decoded, 'wad-unpacked.lua');
        }

        const dump = header + `-- Could not reconstruct payload. Raw strings:\n\n` +
          result.strings.map((s, i) => `[${i+1}] ${JSON.stringify(s).slice(0, 300)}`).join('\n');
        return sendOutput(interaction, dump, 'wad-strings.txt');
      }
    } catch (err) {
      console.error(err);
      const msg = `Error: ${err.message}`;
      if (interaction.deferred || interaction.replied) interaction.editReply(msg).catch(() => {});
      else interaction.reply({ content: msg, flags: MessageFlags.Ephemeral }).catch(() => {});
    }
  });

  process.on('unhandledRejection', e => console.error('unhandled:', e));
  process.on('uncaughtException',  e => console.error('uncaught:', e));

  await client.login(DISCORD_TOKEN);
}

// ==================== ENTRY ====================

if (process.argv[2] === 'register') {
  registerCommands();
} else {
  startBot();
}
