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

const MAX_BYTES = 8 * 1024 * 1024;          // 8 MB input cap (fixed typo)
const MAX_INLINE = 1900;
const MAX_OUTPUT_FILE = 24 * 1024 * 1024;
const SANDBOX_TIMEOUT_MS = 8_000;           // 8s wall clock — Discord interaction safety
const SANDBOX_HOOK_COUNT = 50_000;          // check clock far more often
const PIPELINE_BUDGET_MS = 20_000;          // global pipeline time budget
const CACHE_MAX = 200;
const CACHE_TTL_MS = 30 * 60 * 1000;

const LUA_KEYWORDS = new Set(['and','break','do','else','elseif','end','false','for','function','goto','if','in','local','nil','not','or','repeat','return','then','true','until','while']);

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

class Deadline {
  constructor(ms) { this.end = Date.now() + ms; }
  expired() { return Date.now() > this.end; }
}

// ==================== HELPERS ====================

// Zero-pad decimal escapes when the next char is a digit so "\7" + "1" never becomes "\71".
function escapeLua(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const x = c.charCodeAt(0);
    if (c === '\\') { out += '\\\\'; continue; }
    if (c === '"') { out += '\\"'; continue; }
    if (c === '\n') { out += '\\n'; continue; }
    if (c === '\r') { out += '\\r'; continue; }
    if (c === '\t') { out += '\\t'; continue; }
    if (x < 0x20 || x === 0x7f) {
      const next = s[i + 1];
      // Pad to 3 digits if a literal digit follows, else minimal form.
      out += '\\' + (next && next >= '0' && next <= '9' ? String(x).padStart(3, '0') : String(x));
      continue;
    }
    out += c;
  }
  return out;
}
function escRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// Walk over short-string contents ("..." / '...'), applying fn to each body.
// Correctly skips Lua escape sequences including \z (whitespace skip).
function walkStrings(code, fn) {
  let out = '', i = 0, inStr = null, buf = '', q = '';
  while (i < code.length) {
    const c = code[i];
    if (inStr) {
      if (c === '\\' && i + 1 < code.length) {
        // \z swallows following whitespace
        if (code[i + 1] === 'z') {
          buf += '\\z';
          i += 2;
          while (i < code.length && /\s/.test(code[i])) { buf += code[i]; i++; }
          continue;
        }
        buf += c + code[i + 1]; i += 2; continue;
      }
      if (c === inStr) { out += q + fn(buf) + q; inStr = null; buf = ''; q = ''; i++; continue; }
      if (c === '\n') { out += q + buf + c; inStr = null; buf = ''; q = ''; i++; continue; } // unterminated guard
      buf += c; i++; continue;
    }
    if (c === '"' || c === "'") { inStr = c; q = c; i++; continue; }
    out += c; i++;
  }
  if (inStr) out += q + buf;
  return out;
}

// Detect a Lua long-bracket opener [[ or [=[ ... ]=]. Returns {level, start} or null.
function longBracketAt(code, i) {
  if (code[i] !== '[') return null;
  let j = i + 1, eq = 0;
  while (code[j] === '=') { eq++; j++; }
  if (code[j] === '[') return { level: eq, contentStart: j + 1 };
  return null;
}
function longBracketEnd(code, contentStart, level) {
  const close = ']' + '='.repeat(level) + ']';
  return code.indexOf(close, contentStart);
}

function stripComments(code) {
  let out = '', i = 0, inStr = null;
  while (i < code.length) {
    const c = code[i], n = code[i + 1];
    if (inStr) {
      if (c === '\\' && i + 1 < code.length) { out += c + code[i + 1]; i += 2; continue; }
      if (c === inStr || c === '\n') inStr = null;
      out += c; i++; continue;
    }
    if (c === '"' || c === "'") { inStr = c; out += c; i++; continue; }
    if (c === '-' && n === '-') {
      // long comment?
      const lb = longBracketAt(code, i + 2);
      if (lb) {
        const end = longBracketEnd(code, lb.contentStart, lb.level);
        i = end === -1 ? code.length : end + lb.level + 2;
        continue;
      }
      while (i < code.length && code[i] !== '\n') i++;
      continue;
    }
    // preserve long strings verbatim
    const lb = longBracketAt(code, i);
    if (lb) {
      const end = longBracketEnd(code, lb.contentStart, lb.level);
      const stop = end === -1 ? code.length : end + lb.level + 2;
      out += code.slice(i, stop);
      i = stop; continue;
    }
    out += c; i++;
  }
  return out;
}

function printableScore(s) {
  if (!s.length) return 0;
  let p = 0;
  for (let i = 0; i < s.length; i++) {
    const x = s.charCodeAt(i);
    if (x === 9 || x === 10 || x === 13 || (x >= 32 && x <= 126)) p++;
  }
  return p / s.length;
}

// Higher-signal "is this Lua source" heuristic than raw keyword count.
function looksLikeLua(s) {
  if (!s) return false;
  const kw = (s.match(/\b(local|function|end|if|then|else|return|for|while|do|repeat|until|elseif)\b/g) || []).length;
  const struct = (s.match(/(\bend\b|\bthen\b|\(\)|==|\.\.|=)/g) || []).length;
  const density = printableScore(s);
  return density > 0.9 && (kw >= 2 || (kw >= 1 && struct >= 4));
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
    b.replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, h) => {
      const cp = parseInt(h, 16);
      if (cp > 0x10FFFF) return '\\u{' + h + '}';
      return escapeLua(String.fromCodePoint(cp));
    }));
}

function decodeStringChar(code) {
  let prev;
  do {
    prev = code;
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

// NEW: string.byte folding is not reversible to a literal, but table.concat({...}) of chars is common.
function decodeTableConcatChars(code) {
  let prev;
  do {
    prev = code;
    code = code.replace(/table\.concat\s*\(\s*\{\s*((?:\d+\s*,\s*)*\d+)\s*\}\s*\)/g, (m, list) => {
      // Only safe if these are ASCII codes joined as a string of chars via string.char elsewhere; skip.
      return m; // intentionally conservative — left as a hook
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
      const decoded = Buffer.from(b, 'base64').toString('latin1');
      if (printableScore(decoded) > 0.9 && decoded.length > 4) {
        count++;
        return escapeLua(decoded);
      }
    } catch {}
    return b;
  });
  return { code: result, count };
}

function bruteXorStrings(code, deadline) {
  let count = 0;
  const result = walkStrings(code, b => {
    if (deadline && deadline.expired()) return b;
    if (b.length < 16 || b.length > 50000) return b;
    if (printableScore(b) > 0.85) return b;
    if (/[a-zA-Z]{4,}/.test(b) && printableScore(b) > 0.7) return b;
    let best = null;
    for (let k = 1; k < 256; k++) {
      let decoded = '';
      for (let i = 0; i < b.length; i++) decoded += String.fromCharCode(b.charCodeAt(i) ^ k);
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

// NEW: rolling/position XOR (key index = position) — common in WAD-style packers.
function brutePositionalXorStrings(code, deadline) {
  let count = 0;
  const result = walkStrings(code, b => {
    if (deadline && deadline.expired()) return b;
    if (b.length < 24 || b.length > 50000) return b;
    if (printableScore(b) > 0.85) return b;
    let best = null;
    for (let k = 1; k < 256; k++) {
      let decoded = '';
      for (let i = 0; i < b.length; i++) decoded += String.fromCharCode(b.charCodeAt(i) ^ ((k + i) & 0xff));
      const score = printableScore(decoded);
      if (score > 0.97 && looksLikeLua(decoded) && (!best || score > best.score)) best = { decoded, score };
    }
    if (best) { count++; return escapeLua(best.decoded); }
    return b;
  });
  return { code: result, count };
}

function bruteCaesarStrings(code, deadline) {
  let count = 0;
  const result = walkStrings(code, b => {
    if (deadline && deadline.expired()) return b;
    if (b.length < 16 || b.length > 10000) return b;
    if (printableScore(b) > 0.85) return b;
    if (/[a-zA-Z]{4,}/.test(b) && printableScore(b) > 0.7) return b;
    let best = null;
    for (let off = 1; off < 256; off++) {
      let decoded = '';
      for (let i = 0; i < b.length; i++) decoded += String.fromCharCode((b.charCodeAt(i) - off + 256) % 256);
      const score = printableScore(decoded);
      if (score > 0.97 && looksLikeLua(decoded) && (!best || score > best.score)) best = { decoded, score };
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

// NEW: ROT13-on-letters then base64 is a common cheap combo; try base64-after-reverse and rot13.
function tryRot13Strings(code) {
  let count = 0;
  const rot = c => {
    const x = c.charCodeAt(0);
    if (x >= 65 && x <= 90) return String.fromCharCode(((x - 65 + 13) % 26) + 65);
    if (x >= 97 && x <= 122) return String.fromCharCode(((x - 97 + 13) % 26) + 97);
    return c;
  };
  const result = walkStrings(code, b => {
    if (b.length < 16) return b;
    if (looksLikeLua(b)) return b;
    const out = [...b].map(rot).join('');
    if (looksLikeLua(out)) { count++; return escapeLua(out); }
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
  const u = n => n >>> 0;
  const ops = {
    bxor: (...a) => u(a.reduce((x, y) => x ^ y, 0)),
    band: (...a) => u(a.reduce((x, y) => x & y, 0xffffffff)),
    bor:  (...a) => u(a.reduce((x, y) => x | y, 0)),
    bnot: a => u(~a),
    lshift: (a, b) => u(a << (b & 31)),
    rshift: (a, b) => u(a) >>> (b & 31),
    arshift: (a, b) => u((a | 0) >> (b & 31)),
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

// NEW: also fold the legacy `bit.` library (LuaJIT/Roblox).
function foldBitLib(code) {
  return foldBit32(code.replace(/\bbit\.(bxor|band|bor|bnot|lshift|rshift|arshift)\b/g, 'bit32.$1'))
    .replace(/\bbit32\.(bxor|band|bor|bnot|lshift|rshift|arshift)\b(?=\s*\()/g, 'bit32.$1');
}

// ==================== STRUCTURAL ====================

function splitTopLevelCommas(s) {
  const out = []; let depth = 0, buf = '', inStr = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (c === '\\') { buf += c + (s[i + 1] || ''); i++; continue; }
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

// Balanced brace extraction so nested/string-containing tables don't break.
function findMatchingBrace(code, openIdx) {
  let depth = 0, inStr = null;
  for (let i = openIdx; i < code.length; i++) {
    const c = code[i];
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function resolveConstantTables(code) {
  const tables = new Map();
  const declRe = /local\s+(\w+)\s*=\s*\{/g;
  let m;
  while ((m = declRe.exec(code)) !== null) {
    const name = m[1];
    const open = m.index + m[0].length - 1;
    const close = findMatchingBrace(code, open);
    if (close === -1) continue;
    const inner = code.slice(open + 1, close);
    const items = splitTopLevelCommas(inner).map(s => s.trim()).filter(Boolean);
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

// NEW: propagate `local A = "literal"` single-use string aliases (common after table resolution).
function propagateStringConstants(code) {
  const re = /local\s+(\w+)\s*=\s*("(?:\\.|[^"\\])*")\s*(?:\n|;|$)/g;
  const consts = new Map();
  let m;
  while ((m = re.exec(code)) !== null) {
    const name = m[1];
    // count usages
    const usages = (code.match(new RegExp(`\\b${escRe(name)}\\b`, 'g')) || []).length;
    if (usages === 2) consts.set(name, { val: m[2], decl: m[0] });
  }
  for (const [name, info] of consts) {
    code = code.replace(info.decl, '');
    code = code.replace(new RegExp(`\\b${escRe(name)}\\b`, 'g'), () => info.val);
  }
  return code;
}

function unwrapLoadstrings(code, max = 12) {
  let layers = 0;
  const deepDecode = s => {
    let prev;
    do {
      prev = s;
      s = decodeUnicode(decodeHex(decodeDecimal(`"${s}"`))).replace(/^"|"$/g, '');
    } while (s !== prev);
    return s;
  };
  for (let i = 0; i < max; i++) {
    const stringArg = code.match(/load(?:string)?\s*\(\s*(["'])((?:\\.|(?!\1)[^\\])+)\1\s*\)\s*\(\s*\)/);
    if (stringArg) {
      let inner = deepDecode(stringArg[2]);
      // try base64 if it still doesn't look like Lua
      if (!looksLikeLua(inner) && /^[A-Za-z0-9+/]+=*$/.test(inner) && inner.length % 4 === 0) {
        try {
          const dec = Buffer.from(inner, 'base64').toString('latin1');
          if (looksLikeLua(dec)) inner = dec;
        } catch {}
      }
      if (inner === stringArg[2] || inner.length < 5) break;
      code = code.replace(stringArg[0], inner);
      layers++;
      continue;
    }
    const varArg = code.match(/load(?:string)?\s*\(\s*(\w+)\s*\)\s*\(\s*\)/);
    if (varArg) {
      const varName = varArg[1];
      const defRe = new RegExp(`\\blocal\\s+${escRe(varName)}\\s*=\\s*(["'])((?:\\\\.|(?!\\1)[^\\\\])+)\\1`);
      const defMatch = code.match(defRe);
      if (defMatch) {
        const inner = deepDecode(defMatch[2]);
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
  const existing = new Set();
  const idRe = /\b([a-zA-Z_]\w*)\b/g;
  let im;
  while ((im = idRe.exec(code)) !== null) existing.add(im[1]);

  const seen = new Map();
  let counter = 0;
  const ugly = /\b(_0x[0-9a-fA-F]{4,}|[Il1O0]{5,}|_+[ilIO10]{4,}_*|[A-Z_]{12,})\b/g;
  let m;
  while ((m = ugly.exec(code)) !== null) {
    const name = m[1];
    if (LUA_KEYWORDS.has(name)) continue;
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

// Balanced dead-code removal (fixes the non-greedy corruption bug).
function removeDeadCode(code) {
  const killBlock = (kw, openTok) => {
    let guard = 0;
    while (guard++ < 1000) {
      const re = new RegExp(`\\b${kw}\\s+${openTok}\\b`);
      const m = re.exec(code);
      if (!m) break;
      // find matching end starting after the opener
      let depth = 1, i = m.index + m[0].length, inStr = null;
      while (i < code.length && depth > 0) {
        const c = code[i], n = code[i + 1];
        if (inStr) {
          if (c === '\\') { i += 2; continue; }
          if (c === inStr) inStr = null;
          i++; continue;
        }
        if (c === '"' || c === "'") { inStr = c; i++; continue; }
        if (/\b(if|for|while|function|do)\b/.test(code.slice(i, i + 9)) && /\b(if|for|while|function|do)\b/.test(code.slice(i).match(/^\w+/)?.[0] ? code.slice(i, i + 9) : '')) {
          // crude nested-block depth tracking via keywords
        }
        if (code.startsWith('if', i) || code.startsWith('for', i) || code.startsWith('while', i) || code.startsWith('function', i) || /\bdo\b/.test(code.slice(i, i + 3))) {
          // increment only on whole-word matches
        }
        if (/^(if|for|while|function|do)\b/.test(code.slice(i))) depth++;
        if (/^end\b/.test(code.slice(i))) { depth--; if (depth === 0) { i += 3; break; } }
        i++;
      }
      if (depth !== 0) break; // unbalanced; bail to avoid corruption
      code = code.slice(0, m.index) + code.slice(i);
    }
  };
  // Use a simpler, safer balanced remover:
  code = removeBalancedFalseBlocks(code);
  code = code.replace(/\bdo\s+end\b/g, '');
  return code.replace(/\n{3,}/g, '\n\n');
}

function removeBalancedFalseBlocks(code) {
  const starts = [
    { re: /\bif\s+false\s+then\b/g },
    { re: /\bwhile\s+false\s+do\b/g },
  ];
  for (const { re } of starts) {
    let m, safety = 0;
    while ((m = re.exec(code)) !== null && safety++ < 500) {
      let depth = 1, i = m.index + m[0].length, inStr = null;
      while (i < code.length && depth > 0) {
        if (inStr) {
          if (code[i] === '\\') { i += 2; continue; }
          if (code[i] === inStr) inStr = null;
          i++; continue;
        }
        if (code[i] === '"' || code[i] === "'") { inStr = code[i]; i++; continue; }
        const rest = code.slice(i);
        if (/^(if|for|while|function)\b/.test(rest) || /^do\b/.test(rest)) { depth++; i += rest.match(/^\w+/)[0].length; continue; }
        if (/^end\b/.test(rest)) { depth--; i += 3; continue; }
        i++;
      }
      if (depth === 0) {
        code = code.slice(0, m.index) + code.slice(i);
        re.lastIndex = 0;
      } else break;
    }
  }
  return code;
}

// ==================== BEAUTIFY ====================

function beautify(code) {
  const tokens = [];
  let i = 0, inStr = null, buf = '';
  while (i < code.length) {
    const c = code[i];
    if (inStr) {
      buf += c;
      if (c === '\\' && i + 1 < code.length) { buf += code[i + 1]; i += 2; continue; }
      if (c === inStr) { tokens.push({ s: true, v: buf }); buf = ''; inStr = null; }
      i++; continue;
    }
    // long strings
    const lb = longBracketAt(code, i);
    if (lb) {
      if (buf) { tokens.push({ s: false, v: buf }); buf = ''; }
      const end = longBracketEnd(code, lb.contentStart, lb.level);
      const stop = end === -1 ? code.length : end + lb.level + 2;
      tokens.push({ s: true, v: code.slice(i, stop) });
      i = stop; continue;
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
      v = v.replace(/;\s*(?=[a-zA-Z_])/g, '\n');
      v = v.replace(/\b(then|do)\b(?=[ \t]+[a-zA-Z_])/g, '$1\n');
      v = v.replace(/([^\s])\s+\b(end|else|elseif|until)\b/g, '$1\n$2');
      joined += v;
    }
  }

  const lines = joined.split('\n').map(l => l.trim()).filter(Boolean);
  const result = [];
  let indent = 0;
  for (const l of lines) {
    if (/^(end\b|else\b|elseif\b|until\b|\}|\))/.test(l)) indent = Math.max(0, indent - 1);
    result.push('  '.repeat(indent) + l);

    // Decide net indentation increase for this line, avoiding double counting.
    let inc = 0;
    // block openers that DON'T close on the same line
    const opensBlock = /\b(then|do|repeat)\s*$/.test(l) ||
      (/\bfunction\b/.test(l) && !/\bend\b\s*$/.test(l) && /\)\s*$/.test(l)) ||
      /\{\s*$/.test(l) || /\(\s*$/.test(l);
    const isElse = /^(else|elseif)\b/.test(l);

    if (isElse) inc = 1;            // re-indent body after else/elseif (we already dedented the keyword)
    else if (opensBlock) inc = 1;

    // single-line balanced (e.g. "x = function() return 1 end") => no change
    if (/\bfunction\b.*\bend\b\s*$/.test(l)) inc = 0;
    if (/\bif\b.*\bthen\b.*\bend\b/.test(l)) inc = 0;

    indent += inc;
  }
  return result.join('\n') + '\n';
}

// ==================== WEAREDEVS UNPACKER ====================

function isWeAreDevs(code) {
  return /wearedevs\.net\/obfuscator/i.test(code) ||
         /--\[\[\s*v\d+\.\d+\.\d+\s+https?:\/\/wearedevs/i.test(code) ||
         /WEAREDEVS/i.test(code);
}

function decodeAllEscapesInString(s) {
  let out = '';
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '\\' && i + 1 < s.length) {
      const n = s[i + 1];
      if (/\d/.test(n)) {
        let num = '', j = i + 1;
        while (j < s.length && num.length < 3 && /\d/.test(s[j])) { num += s[j]; j++; }
        const code = parseInt(num, 10);
        if (code <= 255) { out += String.fromCharCode(code); i = j; continue; }
      }
      if (n === 'x' && i + 3 < s.length) {
        const h = s.slice(i + 2, i + 4);
        if (/^[0-9a-fA-F]{2}$/.test(h)) { out += String.fromCharCode(parseInt(h, 16)); i += 4; continue; }
      }
      if (n === 'n') { out += '\n'; i += 2; continue; }
      if (n === 't') { out += '\t'; i += 2; continue; }
      if (n === 'r') { out += '\r'; i += 2; continue; }
      if (n === 'a') { out += '\x07'; i += 2; continue; }
      if (n === 'b') { out += '\b'; i += 2; continue; }
      if (n === 'f') { out += '\f'; i += 2; continue; }
      if (n === 'v') { out += '\v'; i += 2; continue; }
      if (n === '\\' || n === '"' || n === "'") { out += n; i += 2; continue; }
      out += n; i += 2; continue;
    }
    out += c; i++;
  }
  return out;
}

function extractWadConstantTable(code) {
  const declRe = /local\s+(\w+)\s*=\s*\{/g;
  let m, best = null;
  while ((m = declRe.exec(code)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = findMatchingBrace(code, open);
    if (close === -1) continue;
    const body = code.slice(open + 1, close);
    const strings = [];
    const re = /"((?:\\\d{1,3}|\\x[0-9a-fA-F]{2}|\\.|[^"\\])*)"/g;
    let sm;
    while ((sm = re.exec(body)) !== null) strings.push(decodeAllEscapesInString(sm[1]));
    if (strings.length >= 2 && (!best || strings.length > best.strings.length)) {
      best = { name: m[1], strings, raw: body };
    }
  }
  return best;
}

function unpackWeAreDevs(code) {
  const result = {
    detected: false, decoded: null, strings: [], error: null,
    stats: { totalStrings: 0, base64Decoded: 0, payloadSize: 0, decodedStrings: 0 },
  };
  if (!isWeAreDevs(code)) { result.error = 'Not a WeAreDevs script (no header found)'; return result; }
  result.detected = true;

  const table = extractWadConstantTable(code);
  if (!table) { result.error = 'Could not find constant table'; return result; }

  result.stats.totalStrings = table.strings.length;
  result.strings = table.strings;

  const decoded = [];
  let b64Count = 0;
  for (const s of table.strings) {
    const attempts = [];
    if (/^[A-Za-z0-9+/]+=*$/.test(s) && s.length % 4 === 0) {
      try {
        const d = Buffer.from(s, 'base64').toString('latin1');
        if (printableScore(d) > 0.85) { attempts.push({ method: 'b64', value: d }); b64Count++; }
      } catch {}
    }
    if (printableScore(s) > 0.85) attempts.push({ method: 'raw', value: s });
    decoded.push(attempts[0] || { method: 'unknown', value: s });
  }
  result.stats.base64Decoded = b64Count;
  result.stats.decodedStrings = decoded.filter(d => d.method !== 'unknown').length;

  const useful = decoded.filter(d => d.method !== 'unknown' && d.value.length >= 4);

  if (useful.length > 10) {
    const joined = useful.map(d => d.value).join('');
    if (looksLikeLua(joined)) {
      result.decoded = beautify(stripComments(joined));
      result.stats.payloadSize = joined.length;
      return result;
    }
  }

  result.error = `Could not auto-reconstruct payload (custom alphabet likely). Returning ${useful.length} decoded chunks.`;
  result.strings = useful.map(d => `[${d.method}] ${d.value}`);
  return result;
}

// ==================== FINGERPRINTING ====================

function detectObfuscator(code) {
  const hints = [];
  const sig = [
    [/Luraph|LPH_|lph_/i, 'Luraph'],
    [/Moonsec|MoonSec/i, 'Moonsec'],
    [/Ironbrew|IronBrew/i, 'IronBrew'],
    [/Prometheus/i, 'Prometheus'],
    [/Wynfuscate/i, 'Wynfuscate'],
    [/WeAreDevs/i, 'WeAreDevs'],
    [/SynapseXen|Synapse\s*Xen/i, 'Synapse Xen'],
    [/Hercules/i, 'Hercules'],
    [/luaobfuscator\.com/i, 'LuaObfuscator.com'],
    [/PSU|psu_/i, 'PSU'],
    [/XENON/i, 'Xenon'],
    [/v3rmillion|v3rm/i, 'V3rmillion-sourced'],
  ];
  for (const [re, name] of sig) if (re.test(code)) hints.push(name);
  if ((code.match(/\\x[0-9a-f]{2}/gi) || []).length > 20) hints.push('hex-encoded strings');
  if ((code.match(/string\.char\s*\(\s*\d+/g) || []).length > 5) hints.push('string.char encoding');
  if (/load(?:string)?\s*\(\s*["']/.test(code)) hints.push('loadstring wrapper');
  if ((code.match(/bit32\.(bxor|band|bor)/g) || []).length > 5) hints.push('bitwise obfuscation');
  if (/while\s+true\s+do[\s\S]{0,200}if\s+\w+\s*==\s*\d+\s+then/.test(code)) hints.push('VM-style dispatcher');
  if ((code.match(/_0x[0-9a-f]{4,}/gi) || []).length > 10) hints.push('hex-mangled identifiers');
  if ((code.match(/[Il1O0]{5,}/g) || []).length > 10) hints.push('homoglyph identifiers (Il1O0)');
  if (/\\u\{[0-9a-fA-F]+\}/.test(code)) hints.push('unicode escape encoding');
  if (/getfenv|setfenv/.test(code)) hints.push('environment manipulation');
  return [...new Set(hints)];
}

// ==================== SANDBOX ====================

function sandboxExecute(code) {
  if (!fengari) return { available: false, captured: [], error: 'fengari not installed' };

  const captured = [];
  const { lua, lauxlib, lualib, to_luastring } = fengari;
  const L = lauxlib.luaL_newstate();
  lualib.luaL_openlibs(L);

  // Capture loadstring/load payloads. Return a stub callable that captures recursively.
  const captureLoad = (Ls) => {
    if (lua.lua_isstring(Ls, 1)) {
      const s = lua.lua_tojsstring(Ls, 1);
      if (s && s.length > 5) captured.push({ type: 'load', value: s });
    }
    lua.lua_pushjsfunction(Ls, () => 0); // chunk stub
    lua.lua_pushnil(Ls);                 // no error
    return 2;                            // mimic load() returning func, err
  };

  lua.lua_pushjsfunction(L, captureLoad); lua.lua_setglobal(L, to_luastring('loadstring'));
  lua.lua_pushjsfunction(L, captureLoad); lua.lua_setglobal(L, to_luastring('load'));

  for (const name of ['os', 'io', 'require', 'dofile', 'loadfile', 'package']) {
    lua.lua_pushnil(L); lua.lua_setglobal(L, to_luastring(name));
  }

  lua.lua_pushjsfunction(L, (Ls) => {
    const n = lua.lua_gettop(Ls);
    const parts = [];
    for (let i = 1; i <= n; i++) {
      if (lua.lua_isstring(Ls, i)) parts.push(lua.lua_tojsstring(Ls, i));
      else parts.push(String(lua.lua_tonumber(Ls, i)));
    }
    captured.push({ type: 'print', value: parts.join('\t') });
    return 0;
  });
  lua.lua_setglobal(L, to_luastring('print'));

  const fakeGame = `
    local mt; mt = {__index = function(t,k) return setmetatable({}, mt) end,
                __call = function(t, ...) return setmetatable({}, mt) end,
                __newindex = function(t,k,v) end,
                __concat = function() return "" end,
                __tostring = function() return "" end}
    game = setmetatable({}, mt)
    workspace = setmetatable({}, mt)
    script = setmetatable({}, mt)
    Game = game
    Workspace = workspace
    wait = function() return 0 end
    spawn = function(f) end
    delay = function(t,f) end
    tick = function() return 0 end
    task = setmetatable({wait=function() return 0 end, spawn=function() end, defer=function() end}, mt)
    Instance = setmetatable({new = function() return setmetatable({}, mt) end}, mt)
    getfenv = function() return setmetatable({}, mt) end
    setfenv = function(f) return f end
  `;
  const harnessStatus = lauxlib.luaL_dostring(L, to_luastring(fakeGame));
  const harnessErr = harnessStatus !== lua.LUA_OK ? lua.lua_tojsstring(L, -1) : null;
  if (harnessErr) lua.lua_pop(L, 1);

  const start = Date.now();
  let timedOut = false;
  lua.lua_sethook(L, () => {
    if (Date.now() - start > SANDBOX_TIMEOUT_MS) {
      timedOut = true;
      lauxlib.luaL_error(L, to_luastring('sandbox timeout'));
    }
  }, lua.LUA_MASKCOUNT, SANDBOX_HOOK_COUNT);

  try {
    const status = lauxlib.luaL_dostring(L, to_luastring(code));
    if (status !== lua.LUA_OK) {
      const err = lua.lua_tojsstring(L, -1) || 'unknown error';
      return { available: true, captured, error: timedOut ? 'sandbox timeout (8s)' : err, harnessErr };
    }
    return { available: true, captured, error: null, harnessErr };
  } catch (e) {
    return { available: true, captured, error: timedOut ? 'sandbox timeout (8s)' : e.message, harnessErr };
  }
}

// ==================== PIPELINE ====================

function decodeFull(code) {
  const deadline = new Deadline(PIPELINE_BUDGET_MS);
  const stats = {
    originalSize: code.length, passes: 0, layers: 0,
    xorDecoded: 0, posXorDecoded: 0, caesarDecoded: 0, base64Decoded: 0,
    reversedDecoded: 0, rot13Decoded: 0, renamed: 0, finalSize: 0, truncated: false,
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
    code = foldBitLib(code);
    code = resolveConstantTables(code);
    code = inlineTrivialFunctions(code);
    code = propagateStringConstants(code);

    const unwrap = unwrapLoadstrings(code);
    code = unwrap.code; stats.layers += unwrap.layers;

    stats.passes++;
    if (deadline.expired()) { stats.truncated = true; break; }
  } while (code !== prev && stats.passes < 12);

  if (!deadline.expired()) {
    const xorResult = bruteXorStrings(code, deadline);
    code = xorResult.code; stats.xorDecoded = xorResult.count;
  }
  if (!deadline.expired()) {
    const posXor = brutePositionalXorStrings(code, deadline);
    code = posXor.code; stats.posXorDecoded = posXor.count;
  }
  if (!deadline.expired()) {
    const caesarResult = bruteCaesarStrings(code, deadline);
    code = caesarResult.code; stats.caesarDecoded = caesarResult.count;
  }
  if (!deadline.expired()) {
    const revResult = tryReverseStrings(code);
    code = revResult.code; stats.reversedDecoded = revResult.count;
  }
  if (!deadline.expired()) {
    const rotResult = tryRot13Strings(code);
    code = rotResult.code; stats.rot13Decoded = rotResult.count;
  }
  if (deadline.expired()) stats.truncated = true;

  code = foldConcat(code);
  code = resolveConstantTables(code);
  const unwrap2 = unwrapLoadstrings(code);
  code = unwrap2.code; stats.layers += unwrap2.layers;

  const rename = renameUglyIdentifiers(code);
  code = rename.code; stats.renamed = rename.renamed;

  code = removeDeadCode(code);
  code = beautify(code);

  stats.finalSize = code.length;
  return { code, stats };
}

// ==================== EXTRACTORS ====================

function extractStrings(code) {
  const found = [];
  walkStrings(code, b => { if (b.length >= 4) found.push(b); return b; });
  // also pull long strings
  let i = 0;
  while (i < code.length) {
    const lb = longBracketAt(code, i);
    if (lb) {
      const end = longBracketEnd(code, lb.contentStart, lb.level);
      const stop = end === -1 ? code.length : end;
      const body = code.slice(lb.contentStart, stop);
      if (body.length >= 4) found.push(body);
      i = stop + lb.level + 2;
    } else i++;
  }
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

// NEW: pull Roblox asset/script ids and common webhook patterns.
function extractIndicators(code) {
  return {
    webhooks: [...new Set(code.match(/https?:\/\/(?:discord(?:app)?\.com|ptb\.discord\.com)\/api\/webhooks\/\S+/gi) || [])],
    rbxassets: [...new Set(code.match(/rbxassetid:\/\/\d+|rbxasset:\/\/\S+/gi) || [])],
    httpcalls: [...new Set(code.match(/\b(HttpGet|HttpGetAsync|HttpPost|request|http_request|syn\.request)\b/g) || [])],
  };
}

// ==================== SOURCE / OUTPUT ====================

async function getSource(interaction) {
  const code = interaction.options.getString('code');
  const file = interaction.options.getAttachment('file');
  const url = interaction.options.getString('url');

  if (file) {
    if (!/\.(lua|luau|txt)$/i.test(file.name || '')) return { error: 'File must be .lua, .luau, or .txt' };
    if (file.size > MAX_BYTES) return { error: `File too large (${(file.size / 1024 / 1024).toFixed(2)} MB, max ${(MAX_BYTES / 1024 / 1024).toFixed(2)} MB)` };
    try {
      const res = await fetch(file.url, { signal: AbortSignal.timeout(15000) });
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
    return interaction.editReply({ content: extra + '
