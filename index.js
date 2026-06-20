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

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_INLINE = 1900;
const MAX_OUTPUT_FILE = 24 * 1024 * 1024;
const SANDBOX_TIMEOUT_MS = 8_000;
const PIPELINE_TIMEOUT_MS = 30_000;
const CACHE_MAX = 200;
const CACHE_TTL_MS = 30 * 60 * 1000;
const MAX_PIPELINE_ITER = 25;

const LUA_KEYWORDS = new Set([
  'and','break','do','else','elseif','end','false','for','function','goto',
  'if','in','local','nil','not','or','repeat','return','then','true','until','while',
]);

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

// ==================== LEXER (proper Lua tokenizer) ====================
//
// Replaces regex-based string handling. Handles:
//   - "..." and '...' with all escapes
//   - [[...]] and [=[...]=] long strings
//   - -- comments and --[[...]] long comments
//   - numbers (hex, float, exponent)
//   - identifiers, keywords, operators, punctuation
//
// This is the foundation that makes everything else reliable.

const TOK = Object.freeze({
  STR: 'str', LSTR: 'lstr', NUM: 'num', ID: 'id', KW: 'kw',
  OP: 'op', PUNC: 'punc', COMMENT: 'comment', LCOMMENT: 'lcomment',
  WS: 'ws', NL: 'nl', EOF: 'eof',
});

function lex(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;

  const peek = (o = 0) => src[i + o];
  const startsWith = s => src.startsWith(s, i);

  while (i < n) {
    const c = src[i];

    // newline
    if (c === '\n') { tokens.push({ t: TOK.NL, v: '\n', p: i }); i++; continue; }

    // whitespace
    if (c === ' ' || c === '\t' || c === '\r') {
      let j = i;
      while (j < n && (src[j] === ' ' || src[j] === '\t' || src[j] === '\r')) j++;
      tokens.push({ t: TOK.WS, v: src.slice(i, j), p: i });
      i = j; continue;
    }

    // long bracket open: [, [=*[
    if (c === '[') {
      let eq = 0, j = i + 1;
      while (j < n && src[j] === '=') { eq++; j++; }
      if (src[j] === '[') {
        const closer = ']' + '='.repeat(eq) + ']';
        const end = src.indexOf(closer, j + 1);
        const stop = end === -1 ? n : end + closer.length;
        tokens.push({ t: TOK.LSTR, v: src.slice(i, stop), eq, body: src.slice(j + 1, end === -1 ? n : end), p: i });
        i = stop; continue;
      }
      tokens.push({ t: TOK.PUNC, v: '[', p: i }); i++; continue;
    }

    // comments
    if (c === '-' && peek(1) === '-') {
      // long comment?
      if (src[i+2] === '[') {
        let eq = 0, j = i + 3;
        while (j < n && src[j] === '=') { eq++; j++; }
        if (src[j] === '[') {
          const closer = ']' + '='.repeat(eq) + ']';
          const end = src.indexOf(closer, j + 1);
          const stop = end === -1 ? n : end + closer.length;
          tokens.push({ t: TOK.LCOMMENT, v: src.slice(i, stop), p: i });
          i = stop; continue;
        }
      }
      let j = i;
      while (j < n && src[j] !== '\n') j++;
      tokens.push({ t: TOK.COMMENT, v: src.slice(i, j), p: i });
      i = j; continue;
    }

    // short strings
    if (c === '"' || c === "'") {
      const quote = c;
      let j = i + 1;
      let body = '';
      while (j < n) {
        const ch = src[j];
        if (ch === '\\' && j + 1 < n) { body += ch + src[j+1]; j += 2; continue; }
        if (ch === quote) { j++; break; }
        if (ch === '\n') break; // unterminated, recover
        body += ch; j++;
      }
      tokens.push({ t: TOK.STR, v: src.slice(i, j), q: quote, body, p: i });
      i = j; continue;
    }

    // numbers
    if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(peek(1)))) {
      let j = i;
      if (c === '0' && (peek(1) === 'x' || peek(1) === 'X')) {
        j += 2;
        while (j < n && /[0-9a-fA-F.]/.test(src[j])) j++;
        if (src[j] === 'p' || src[j] === 'P') {
          j++; if (src[j] === '+' || src[j] === '-') j++;
          while (j < n && /[0-9]/.test(src[j])) j++;
        }
      } else {
        while (j < n && /[0-9.]/.test(src[j])) j++;
        if (src[j] === 'e' || src[j] === 'E') {
          j++; if (src[j] === '+' || src[j] === '-') j++;
          while (j < n && /[0-9]/.test(src[j])) j++;
        }
      }
      tokens.push({ t: TOK.NUM, v: src.slice(i, j), p: i });
      i = j; continue;
    }

    // identifier or keyword
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
      const v = src.slice(i, j);
      tokens.push({ t: LUA_KEYWORDS.has(v) ? TOK.KW : TOK.ID, v, p: i });
      i = j; continue;
    }

    // multi-char operators
    const three = src.slice(i, i+3);
    if (three === '...' || three === '..=' || three === '>>=' || three === '<<=') {
      tokens.push({ t: TOK.OP, v: three, p: i }); i += 3; continue;
    }
    const two = src.slice(i, i+2);
    if (['==','~=','<=','>=','::','..','->','<<','>>','+=','-=','*=','/=','%=','^=','//'].includes(two)) {
      tokens.push({ t: TOK.OP, v: two, p: i }); i += 2; continue;
    }

    // single char punc/op
    if ('+-*/%^#<>=~&|'.includes(c)) { tokens.push({ t: TOK.OP, v: c, p: i }); i++; continue; }
    if ('(){}[];,.:'.includes(c))   { tokens.push({ t: TOK.PUNC, v: c, p: i }); i++; continue; }

    // unknown byte — keep as-is
    tokens.push({ t: TOK.PUNC, v: c, p: i }); i++;
  }

  tokens.push({ t: TOK.EOF, v: '', p: n });
  return tokens;
}

function rebuild(tokens) {
  let out = '';
  for (const t of tokens) {
    if (t.t === TOK.EOF) continue;
    if (t.t === TOK.STR) out += (t.q || '"') + t.body + (t.body.endsWith('\\') ? '' : '') + (t.q || '"');
    else out += t.v;
  }
  return out;
}

function makeStr(body, quote = '"') {
  const q = quote;
  const escaped = body
    .replace(/\\/g, '\\\\')
    .replace(new RegExp(q, 'g'), '\\' + q)
    .replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, c => '\\' + c.charCodeAt(0));
  return { t: TOK.STR, v: q + escaped + q, q, body: escaped, p: 0 };
}

function decodeStrEscapes(body) {
  let out = '', i = 0;
  while (i < body.length) {
    const c = body[i];
    if (c !== '\\') { out += c; i++; continue; }
    const n = body[i+1];
    if (n === undefined) { out += c; i++; continue; }
    if (n === 'x' && /^[0-9a-fA-F]{2}$/.test(body.slice(i+2, i+4))) {
      out += String.fromCharCode(parseInt(body.slice(i+2, i+4), 16)); i += 4; continue;
    }
    if (n === 'u' && body[i+2] === '{') {
      const end = body.indexOf('}', i+3);
      if (end !== -1) {
        const cp = parseInt(body.slice(i+3, end), 16);
        if (!isNaN(cp)) { out += String.fromCodePoint(cp); i = end + 1; continue; }
      }
    }
    if (/[0-9]/.test(n)) {
      let num = '', j = i + 1;
      while (j < body.length && num.length < 3 && /[0-9]/.test(body[j])) { num += body[j]; j++; }
      const code = parseInt(num, 10);
      if (code <= 255) { out += String.fromCharCode(code); i = j; continue; }
    }
    if (n === 'n') { out += '\n'; i += 2; continue; }
    if (n === 'r') { out += '\r'; i += 2; continue; }
    if (n === 't') { out += '\t'; i += 2; continue; }
    if (n === 'a') { out += '\x07'; i += 2; continue; }
    if (n === 'b') { out += '\b'; i += 2; continue; }
    if (n === 'f') { out += '\f'; i += 2; continue; }
    if (n === 'v') { out += '\v'; i += 2; continue; }
    if (n === '\\' || n === '"' || n === "'" || n === '\n') { out += n; i += 2; continue; }
    if (n === 'z') {
      i += 2;
      while (i < body.length && /\s/.test(body[i])) i++;
      continue;
    }
    out += n; i += 2;
  }
  return out;
}

// ==================== TOKEN HELPERS ====================

function forEachString(tokens, fn) {
  let changed = 0;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.t !== TOK.STR && t.t !== TOK.LSTR) continue;
    const decoded = t.t === TOK.STR ? decodeStrEscapes(t.body) : t.body;
    const replacement = fn(decoded, t);
    if (replacement === null || replacement === undefined) continue;
    if (replacement === decoded) continue;
    tokens[i] = makeStr(replacement);
    changed++;
  }
  return changed;
}

function nextNonTrivia(tokens, i) {
  for (let j = i + 1; j < tokens.length; j++) {
    const t = tokens[j];
    if (t.t === TOK.WS || t.t === TOK.NL || t.t === TOK.COMMENT || t.t === TOK.LCOMMENT) continue;
    return { tok: t, idx: j };
  }
  return { tok: null, idx: -1 };
}

function prevNonTrivia(tokens, i) {
  for (let j = i - 1; j >= 0; j--) {
    const t = tokens[j];
    if (t.t === TOK.WS || t.t === TOK.NL || t.t === TOK.COMMENT || t.t === TOK.LCOMMENT) continue;
    return { tok: t, idx: j };
  }
  return { tok: null, idx: -1 };
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

function looksLikeLua(s) {
  const kw = /\b(local|function|end|if|then|else|return|for|while|do|repeat|until|elseif|require|loadstring)\b/g;
  const matches = s.match(kw);
  return matches && matches.length >= 2;
}

function stripTrivia(tokens, keep = { comments: false, ws: true, nl: true }) {
  return tokens.filter(t => {
    if (t.t === TOK.COMMENT || t.t === TOK.LCOMMENT) return keep.comments;
    if (t.t === TOK.WS) return keep.ws;
    if (t.t === TOK.NL) return keep.nl;
    return true;
  });
}

// ==================== ENGINES ====================
//
// Each engine: { name, priority, detect(tokens, src) -> 0..1, run(tokens, src, ctx) -> { tokens, changed, info } }
// The pipeline applies engines in priority order, repeats until fixed-point or budget exhausted.

const engines = [];

function registerEngine(e) { engines.push(e); engines.sort((a, b) => a.priority - b.priority); }

// --- Engine: strip comments ---
registerEngine({
  name: 'strip-comments',
  priority: 5,
  detect: () => 1,
  run(tokens) {
    let changed = 0;
    const out = tokens.filter(t => {
      if (t.t === TOK.COMMENT || t.t === TOK.LCOMMENT) { changed++; return false; }
      return true;
    });
    return { tokens: out, changed, info: changed ? `${changed} comments` : null };
  },
});

// --- Engine: decode string escapes (\x \ddd \u{}) ---
registerEngine({
  name: 'string-escapes',
  priority: 10,
  detect: (tokens, src) => /\\(x[0-9a-fA-F]{2}|\d{1,3}|u\{[0-9a-fA-F]+\})/.test(src) ? 1 : 0,
  run(tokens) {
    let changed = 0;
    forEachString(tokens, (decoded, t) => {
      if (t.t !== TOK.STR) return null;
      // re-encode cleanly (lossy reversal removes escape sequences)
      return decoded;
    });
    // count by comparing raw bodies; conservative
    return { tokens, changed, info: null };
  },
});

// --- Engine: string.char(...) collapse ---
registerEngine({
  name: 'string.char',
  priority: 15,
  detect: (tokens, src) => /string\.char\s*\(/.test(src) ? 1 : 0,
  run(tokens) {
    let changed = 0;
    // Walk tokens, find sequence: ID(string) . ID(char) ( NUM , NUM , ... )
    for (let i = 0; i < tokens.length - 5; i++) {
      if (tokens[i].t !== TOK.ID || tokens[i].v !== 'string') continue;
      const dot = nextNonTrivia(tokens, i);
      if (!dot.tok || dot.tok.v !== '.') continue;
      const fn = nextNonTrivia(tokens, dot.idx);
      if (!fn.tok || fn.tok.v !== 'char') continue;
      const lp = nextNonTrivia(tokens, fn.idx);
      if (!lp.tok || lp.tok.v !== '(') continue;

      // collect numbers until matching ')'
      const nums = [];
      let j = lp.idx + 1, depth = 1, ok = true;
      while (j < tokens.length && depth > 0) {
        const tt = tokens[j];
        if (tt.t === TOK.WS || tt.t === TOK.NL) { j++; continue; }
        if (tt.v === '(') { depth++; j++; continue; }
        if (tt.v === ')') { depth--; if (depth === 0) break; j++; continue; }
        if (tt.v === ',') { j++; continue; }
        if (tt.t === TOK.NUM) {
          const n = parseInt(tt.v, 10);
          if (isNaN(n) || n < 0 || n > 255) { ok = false; break; }
          nums.push(n); j++; continue;
        }
        if (tt.t === TOK.OP && tt.v === '-') {
          const nxt = nextNonTrivia(tokens, j);
          if (nxt.tok && nxt.tok.t === TOK.NUM) {
            const n = -parseInt(nxt.tok.v, 10);
            if (isNaN(n) || n < 0 || n > 255) { ok = false; break; }
            nums.push(n); j = nxt.idx + 1; continue;
          }
        }
        ok = false; break;
      }
      if (!ok || nums.length === 0 || depth !== 0) continue;

      const str = nums.map(n => String.fromCharCode(n)).join('');
      const newTok = makeStr(str);
      tokens.splice(i, j - i + 1, newTok);
      changed++;
    }
    return { tokens, changed, info: changed ? `${changed} string.char` : null };
  },
});

// --- Engine: string concat folding ---
registerEngine({
  name: 'concat-fold',
  priority: 20,
  detect: () => 1,
  run(tokens) {
    let changed = 0;
    for (let i = 0; i < tokens.length - 2; i++) {
      if (tokens[i].t !== TOK.STR) continue;
      const op = nextNonTrivia(tokens, i);
      if (!op.tok || op.tok.v !== '..') continue;
      const rhs = nextNonTrivia(tokens, op.idx);
      if (!rhs.tok || rhs.tok.t !== TOK.STR) continue;
      const combined = decodeStrEscapes(tokens[i].body) + decodeStrEscapes(rhs.tok.body);
      const merged = makeStr(combined);
      tokens.splice(i, rhs.idx - i + 1, merged);
      changed++;
      i--; // re-check
    }
    return { tokens, changed, info: changed ? `${changed} concats folded` : null };
  },
});

// --- Engine: arithmetic folding ---
registerEngine({
  name: 'arith-fold',
  priority: 25,
  detect: () => 1,
  run(tokens) {
    let changed = 0;
    for (let i = 0; i < tokens.length - 4; i++) {
      // ( NUM OP NUM )
      if (tokens[i].v !== '(') continue;
      const a = nextNonTrivia(tokens, i);
      if (!a.tok || a.tok.t !== TOK.NUM) continue;
      const op = nextNonTrivia(tokens, a.idx);
      if (!op.tok || !'+-*/%^'.includes(op.tok.v)) continue;
      const b = nextNonTrivia(tokens, op.idx);
      if (!b.tok || b.tok.t !== TOK.NUM) continue;
      const cp = nextNonTrivia(tokens, b.idx);
      if (!cp.tok || cp.tok.v !== ')') continue;

      const x = parseFloat(a.tok.v), y = parseFloat(b.tok.v);
      let r;
      switch (op.tok.v) {
        case '+': r = x + y; break;
        case '-': r = x - y; break;
        case '*': r = x * y; break;
        case '/': if (y === 0) continue; r = x / y; break;
        case '%': if (y === 0) continue; r = ((x % y) + y) % y; break;
        case '^': r = Math.pow(x, y); break;
      }
      if (!isFinite(r)) continue;
      const s = Number.isInteger(r) ? String(r) : r.toFixed(6).replace(/\.?0+$/, '');
      tokens.splice(i, cp.idx - i + 1, { t: TOK.NUM, v: s, p: 0 });
      changed++;
      i--;
    }
    return { tokens, changed, info: changed ? `${changed} arith folded` : null };
  },
});

// --- Engine: bit32 folding ---
registerEngine({
  name: 'bit32-fold',
  priority: 30,
  detect: (tokens, src) => /bit32\./.test(src) ? 1 : 0,
  run(tokens) {
    const ops = {
      bxor: a => a.reduce((x, y) => (x ^ y) >>> 0),
      band: a => a.reduce((x, y) => (x & y) >>> 0),
      bor:  a => a.reduce((x, y) => (x | y) >>> 0),
      bnot: a => (~a[0]) >>> 0,
      lshift: a => (a[0] << a[1]) >>> 0,
      rshift: a => (a[0] >>> a[1]),
      arshift: a => (a[0] >> a[1]) >>> 0,
    };
    let changed = 0;
    for (let i = 0; i < tokens.length - 5; i++) {
      if (tokens[i].v !== 'bit32') continue;
      const dot = nextNonTrivia(tokens, i);
      if (!dot.tok || dot.tok.v !== '.') continue;
      const fn = nextNonTrivia(tokens, dot.idx);
      if (!fn.tok || !ops[fn.tok.v]) continue;
      const lp = nextNonTrivia(tokens, fn.idx);
      if (!lp.tok || lp.tok.v !== '(') continue;

      const nums = [];
      let j = lp.idx + 1, depth = 1, ok = true, neg = false;
      while (j < tokens.length && depth > 0) {
        const tt = tokens[j];
        if (tt.t === TOK.WS || tt.t === TOK.NL) { j++; continue; }
        if (tt.v === '(') { depth++; j++; continue; }
        if (tt.v === ')') { depth--; if (depth === 0) break; j++; continue; }
        if (tt.v === ',') { neg = false; j++; continue; }
        if (tt.t === TOK.OP && tt.v === '-') { neg = !neg; j++; continue; }
        if (tt.t === TOK.NUM) {
          const n = (neg ? -1 : 1) * parseInt(tt.v, 10);
          if (isNaN(n)) { ok = false; break; }
          nums.push(n >>> 0); neg = false; j++; continue;
        }
        ok = false; break;
      }
      if (!ok || nums.length === 0 || depth !== 0) continue;

      try {
        const r = ops[fn.tok.v](nums);
        tokens.splice(i, j - i + 1, { t: TOK.NUM, v: String(r), p: 0 });
        changed++;
        i--;
      } catch { /* skip */ }
    }
    return { tokens, changed, info: changed ? `${changed} bit32 folded` : null };
  },
});

// --- Engine: base64 string decode ---
registerEngine({
  name: 'base64-strings',
  priority: 40,
  detect: () => 1,
  run(tokens) {
    let changed = 0;
    forEachString(tokens, (decoded) => {
      if (decoded.length < 16 || decoded.length % 4 !== 0) return null;
      if (!/^[A-Za-z0-9+/]+=*$/.test(decoded)) return null;
      try {
        const out = Buffer.from(decoded, 'base64').toString('utf-8');
        if (printableScore(out) > 0.9 && out.length > 4) { changed++; return out; }
      } catch { /* ignore */ }
      return null;
    });
    return { tokens, changed, info: changed ? `${changed} base64` : null };
  },
});

// --- Engine: hex-string decode (long hex blobs like "deadbeef...") ---
registerEngine({
  name: 'hex-blob-strings',
  priority: 41,
  detect: () => 1,
  run(tokens) {
    let changed = 0;
    forEachString(tokens, (decoded) => {
      if (decoded.length < 32 || decoded.length % 2 !== 0) return null;
      if (!/^[0-9a-fA-F]+$/.test(decoded)) return null;
      try {
        const buf = Buffer.from(decoded, 'hex').toString('utf-8');
        if (printableScore(buf) > 0.9) { changed++; return buf; }
      } catch { /* ignore */ }
      return null;
    });
    return { tokens, changed, info: changed ? `${changed} hex blobs` : null };
  },
});

// --- Engine: brute XOR single-byte ---
registerEngine({
  name: 'xor-brute',
  priority: 50,
  detect: () => 1,
  run(tokens) {
    let changed = 0;
    forEachString(tokens, (decoded) => {
      if (decoded.length < 16 || decoded.length > 50000) return null;
      if (printableScore(decoded) > 0.85 && looksLikeLua(decoded)) return null;
      let best = null;
      for (let k = 1; k < 256; k++) {
        let out = '';
        for (let i = 0; i < decoded.length; i++) out += String.fromCharCode(decoded.charCodeAt(i) ^ k);
        if (printableScore(out) > 0.97 && looksLikeLua(out)) {
          const score = printableScore(out);
          if (!best || score > best.score) best = { out, score };
        }
      }
      if (best) { changed++; return best.out; }
      return null;
    });
    return { tokens, changed, info: changed ? `${changed} XOR-decoded` : null };
  },
});

// --- Engine: Caesar single-byte ---
registerEngine({
  name: 'caesar-brute',
  priority: 51,
  detect: () => 1,
  run(tokens) {
    let changed = 0;
    forEachString(tokens, (decoded) => {
      if (decoded.length < 16 || decoded.length > 10000) return null;
      if (printableScore(decoded) > 0.85 && looksLikeLua(decoded)) return null;
      let best = null;
      for (let off = 1; off < 128; off++) {
        let out = '';
        for (let i = 0; i < decoded.length; i++) out += String.fromCharCode((decoded.charCodeAt(i) - off + 256) % 256);
        if (printableScore(out) > 0.97 && looksLikeLua(out)) {
          if (!best || printableScore(out) > best.score) best = { out, score: printableScore(out) };
        }
      }
      if (best) { changed++; return best.out; }
      return null;
    });
    return { tokens, changed, info: changed ? `${changed} Caesar-decoded` : null };
  },
});

// --- Engine: reversed strings ---
registerEngine({
  name: 'reverse-strings',
  priority: 52,
  detect: () => 1,
  run(tokens) {
    let changed = 0;
    forEachString(tokens, (decoded) => {
      if (decoded.length < 16) return null;
      if (printableScore(decoded) > 0.95 && looksLikeLua(decoded)) return null;
      const rev = [...decoded].reverse().join('');
      if (printableScore(rev) > 0.97 && looksLikeLua(rev)) { changed++; return rev; }
      return null;
    });
    return { tokens, changed, info: changed ? `${changed} reversed` : null };
  },
});

// --- Engine: constant table indexing ---
registerEngine({
  name: 'const-tables',
  priority: 60,
  detect: () => 1,
  run(tokens, src) {
    // Find: local NAME = { lit, lit, ... }   then NAME[idx] -> lit
    // Use token scanning, not regex on source.
    const tables = new Map(); // name -> array of token-literals
    for (let i = 0; i < tokens.length - 4; i++) {
      if (tokens[i].t !== TOK.KW || tokens[i].v !== 'local') continue;
      const name = nextNonTrivia(tokens, i);
      if (!name.tok || name.tok.t !== TOK.ID) continue;
      const eq = nextNonTrivia(tokens, name.idx);
      if (!eq.tok || eq.tok.v !== '=') continue;
      const lb = nextNonTrivia(tokens, eq.idx);
      if (!lb.tok || lb.tok.v !== '{') continue;

      const items = [];
      let j = lb.idx + 1, depth = 1, expect = 'val', cur = null;
      while (j < tokens.length && depth > 0) {
        const tt = tokens[j];
        if (tt.t === TOK.WS || tt.t === TOK.NL) { j++; continue; }
        if (tt.v === '{') { depth++; j++; cur = null; continue; }
        if (tt.v === '}') { depth--; if (depth === 0) { if (cur) items.push(cur); break; } j++; continue; }
        if (tt.v === ',' && depth === 1) { if (cur) items.push(cur); cur = null; expect = 'val'; j++; continue; }
        if (depth === 1 && expect === 'val') {
          if (tt.t === TOK.STR || tt.t === TOK.LSTR || tt.t === TOK.NUM ||
              (tt.t === TOK.KW && (tt.v === 'true' || tt.v === 'false' || tt.v === 'nil'))) {
            cur = tt;
          } else { cur = null; expect = 'skip'; }
        }
        j++;
      }
      if (items.length >= 2 && items.every(Boolean)) tables.set(name.tok.v, items);
    }

    if (!tables.size) return { tokens, changed: 0, info: null };

    let changed = 0;
    for (let i = 0; i < tokens.length - 3; i++) {
      if (tokens[i].t !== TOK.ID) continue;
      const lits = tables.get(tokens[i].v);
      if (!lits) continue;
      const lb = nextNonTrivia(tokens, i);
      if (!lb.tok || lb.tok.v !== '[') continue;
      const num = nextNonTrivia(tokens, lb.idx);
      if (!num.tok || num.tok.t !== TOK.NUM) continue;
      const rb = nextNonTrivia(tokens, num.idx);
      if (!rb.tok || rb.tok.v !== ']') continue;
      const idx = parseInt(num.tok.v, 10) - 1;
      if (idx < 0 || idx >= lits.length) continue;
      const lit = lits[idx];
      tokens.splice(i, rb.idx - i + 1, { ...lit });
      changed++;
    }
    return { tokens, changed, info: changed ? `${changed} table reads` : null };
  },
});

// --- Engine: inline trivial constant functions ---
registerEngine({
  name: 'inline-trivial-fns',
  priority: 65,
  detect: () => 1,
  run(tokens) {
    const inlines = new Map();
    for (let i = 0; i < tokens.length - 8; i++) {
      if (tokens[i].v !== 'local') continue;
      const name = nextNonTrivia(tokens, i); if (!name.tok || name.tok.t !== TOK.ID) continue;
      const eq = nextNonTrivia(tokens, name.idx); if (!eq.tok || eq.tok.v !== '=') continue;
      const fn = nextNonTrivia(tokens, eq.idx); if (!fn.tok || fn.tok.v !== 'function') continue;
      const lp = nextNonTrivia(tokens, fn.idx); if (!lp.tok || lp.tok.v !== '(') continue;
      const rp = nextNonTrivia(tokens, lp.idx); if (!rp.tok || rp.tok.v !== ')') continue;
      const ret = nextNonTrivia(tokens, rp.idx); if (!ret.tok || ret.tok.v !== 'return') continue;
      const val = nextNonTrivia(tokens, ret.idx); if (!val.tok) continue;
      if (val.tok.t !== TOK.STR && val.tok.t !== TOK.NUM) continue;
      const end = nextNonTrivia(tokens, val.idx); if (!end.tok || end.tok.v !== 'end') continue;
      inlines.set(name.tok.v, { ...val.tok });
    }
    if (!inlines.size) return { tokens, changed: 0, info: null };

    let changed = 0;
    for (let i = 0; i < tokens.length - 2; i++) {
      if (tokens[i].t !== TOK.ID || !inlines.has(tokens[i].v)) continue;
      const lp = nextNonTrivia(tokens, i); if (!lp.tok || lp.tok.v !== '(') continue;
      const rp = nextNonTrivia(tokens, lp.idx); if (!rp.tok || rp.tok.v !== ')') continue;
      tokens.splice(i, rp.idx - i + 1, { ...inlines.get(tokens[i].v) });
      changed++;
    }
    return { tokens, changed, info: changed ? `${changed} fns inlined` : null };
  },
});

// --- Engine: loadstring unwrap ---
registerEngine({
  name: 'loadstring-unwrap',
  priority: 70,
  detect: (tokens, src) => /load(?:string)?\s*\(/.test(src) ? 1 : 0,
  run(tokens) {
    let changed = 0;
    for (let i = 0; i < tokens.length - 4; i++) {
      const t = tokens[i];
      if (t.t !== TOK.ID || (t.v !== 'load' && t.v !== 'loadstring')) continue;
      const lp = nextNonTrivia(tokens, i); if (!lp.tok || lp.tok.v !== '(') continue;
      const arg = nextNonTrivia(tokens, lp.idx);
      if (!arg.tok || (arg.tok.t !== TOK.STR && arg.tok.t !== TOK.LSTR)) continue;
      const rp = nextNonTrivia(tokens, arg.idx); if (!rp.tok || rp.tok.v !== ')') continue;
      const call = nextNonTrivia(tokens, rp.idx); if (!call.tok || call.tok.v !== '(') continue;
      const callEnd = nextNonTrivia(tokens, call.idx); if (!callEnd.tok || callEnd.tok.v !== ')') continue;

      const inner = arg.tok.t === TOK.STR ? decodeStrEscapes(arg.tok.body) : arg.tok.body;
      if (inner.length < 5) continue;

      // Replace whole loadstring(...)() with inner source as tokens
      const innerTokens = lex(inner);
      innerTokens.pop(); // drop EOF
      tokens.splice(i, callEnd.idx - i + 1, ...innerTokens);
      changed++;
      break; // one per pass — re-run pipeline
    }
    return { tokens, changed, info: changed ? `${changed} layer peeled` : null };
  },
});

// --- Engine: identifier rename ---
registerEngine({
  name: 'rename-ugly',
  priority: 90,
  detect: (tokens, src) => /_0x[0-9a-fA-F]{4,}|[A-Z_]{12,}|_+[ilIO10]{4,}/.test(src) ? 1 : 0,
  run(tokens) {
    const existing = new Set();
    for (const t of tokens) if (t.t === TOK.ID) existing.add(t.v);
    const ugly = /^(_0x[0-9a-fA-F]{4,}|_+[ilIO10]{4,}_*|[A-Z_]{12,})$/;
    const map = new Map();
    let counter = 0;
    for (const t of tokens) {
      if (t.t !== TOK.ID) continue;
      if (LUA_KEYWORDS.has(t.v)) continue;
      if (!ugly.test(t.v)) continue;
      if (map.has(t.v)) continue;
      let candidate;
      do { candidate = `v${++counter}`; } while (existing.has(candidate));
      existing.add(candidate);
      map.set(t.v, candidate);
    }
    if (!map.size) return { tokens, changed: 0, info: null };
    let changed = 0;
    for (const t of tokens) {
      if (t.t === TOK.ID && map.has(t.v)) { t.v = map.get(t.v); changed++; }
    }
    return { tokens, changed, info: `${map.size} identifiers (${changed} refs)` };
  },
});

// ==================== PIPELINE RUNNER ====================

function runPipeline(src, opts = {}) {
  const stats = {
    originalSize: src.length,
    iterations: 0,
    engineRuns: [],
    detected: [],
    finalSize: 0,
    elapsedMs: 0,
  };
  const start = Date.now();

  let tokens = lex(src);
  let totalChanges = 0;

  for (let iter = 0; iter < MAX_PIPELINE_ITER; iter++) {
    if (Date.now() - start > PIPELINE_TIMEOUT_MS) { stats.timedOut = true; break; }
    stats.iterations++;
    let iterChanges = 0;
    const currentSrc = tokens.map(t => t.v).join('');
    for (const eng of engines) {
      const conf = eng.detect(tokens, currentSrc);
      if (conf <= 0) continue;
      const { tokens: newTokens, changed, info } = eng.run(tokens, currentSrc, { iter });
      if (changed > 0) {
        tokens = newTokens;
        iterChanges += changed;
        totalChanges += changed;
        stats.engineRuns.push({ iter, name: eng.name, changed, info });
      }
    }
    if (iterChanges === 0) break;
  }

  // identify obfuscator from original source
  stats.detected = detectObfuscator(src);

  // beautify final output
  const finalSrc = beautify(tokens.map(t => t.v).join(''));
  stats.finalSize = finalSrc.length;
  stats.totalChanges = totalChanges;
  stats.elapsedMs = Date.now() - start;
  return { code: finalSrc, stats };
}

// ==================== BEAUTIFY (token-aware) ====================
//
// Re-lex the result and emit one token per line where appropriate.
// Indent based on block-opening / block-closing keywords.

function beautify(src) {
  const toks = stripTrivia(lex(src), { comments: true, ws: false, nl: false });
  // Build statements: insert newline after `;`, after `end`/`else`/`elseif`/`do`/`then`/`repeat`/`until`,
  // and before `local`/`if`/`for`/`while`/`return`/`function`/`elseif`/`else`/`end`/`until` when not already at line start.

  const out = [];
  const blockOpen = new Set(['do', 'then', 'repeat', 'else', 'function']);
  const blockClose = new Set(['end', 'until', 'elseif', 'else']);
  const stmtStart = new Set(['local', 'if', 'for', 'while', 'return', 'do', 'repeat', 'function']);

  let line = [];
  const flush = () => { if (line.length) { out.push(line); line = []; } };

  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t === TOK.EOF) { flush(); break; }
    if (t.t === TOK.COMMENT || t.t === TOK.LCOMMENT) {
      flush(); out.push([t]); continue;
    }
    if (t.v === ';') { flush(); continue; }
    if (t.t === TOK.KW && stmtStart.has(t.v) && line.length) flush();
    if (t.t === TOK.KW && blockClose.has(t.v) && line.length) flush();
    line.push(t);
    if (t.t === TOK.KW && blockOpen.has(t.v)) flush();
  }
  flush();

  // join with smart spacing
  const spaced = lines => lines.map(toks => {
    let s = '';
    for (let i = 0; i < toks.length; i++) {
      const a = toks[i], b = toks[i+1];
      s += a.t === TOK.STR ? a.v : a.v;
      if (!b) continue;
      if (needsSpace(a, b)) s += ' ';
    }
    return s;
  });

  // indentation
  const indented = [];
  let depth = 0;
  for (const line of spaced(out)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/^(end|until|else|elseif)\b/.test(trimmed)) depth = Math.max(0, depth - 1);
    indented.push('  '.repeat(depth) + trimmed);
    if (/^(else|elseif)\b/.test(trimmed)) depth++;
    if (/\b(then|do|repeat)\s*$/.test(trimmed)) depth++;
    if (/^function\b/.test(trimmed) || /\bfunction\b[^)]*\)\s*$/.test(trimmed)) depth++;
    if (/^local\s+function\b/.test(trimmed) && /\)\s*$/.test(trimmed)) depth++;
  }
  return indented.join('\n') + '\n';
}

function needsSpace(a, b) {
  // Insert a space between tokens that would lex-merge: id/kw/num next to id/kw/num
  const isWord = t => t.t === TOK.ID || t.t === TOK.KW || t.t === TOK.NUM;
  if (isWord(a) && isWord(b)) return true;
  if (a.t === TOK.OP && b.t === TOK.OP) return true;
  if (a.v === ',' || a.v === ';') return true;
  if (a.t === TOK.KW && (b.v === '(' || b.v === '{' || b.t === TOK.STR)) return true;
  if (isWord(a) && (b.v === '=' || b.v === '..' || b.v === '+' || b.v === '-' || b.v === '*' || b.v === '/')) return true;
  if ((a.v === '=' || a.v === '..') && (isWord(b) || b.t === TOK.STR || b.v === '(' || b.v === '{')) return true;
  return false;
}

// ==================== FINGERPRINTING ====================

function detectObfuscator(code) {
  const hints = [];
  const sigs = [
    [/Luraph|LPH_|lph_/i, 'Luraph'],
    [/Moonsec|MoonSec/i, 'Moonsec'],
    [/Ironbrew|IronBrew/i, 'IronBrew'],
    [/Prometheus/i, 'Prometheus'],
    [/Wynfuscate/i, 'Wynfuscate'],
    [/wearedevs\.net\/obfuscator/i, 'WeAreDevs'],
    [/SynapseXen|Synapse\s*Xen/i, 'Synapse Xen'],
    [/Hercules/i, 'Hercules'],
    [/luaobfuscator\.com/i, 'LuaObfuscator.com'],
  ];
  for (const [r, n] of sigs) if (r.test(code)) hints.push(n);

  if ((code.match(/\\x[0-9a-f]{2}/gi) || []).length > 20) hints.push('hex-encoded strings');
  if ((code.match(/string\.char\s*\(\s*\d+/g) || []).length > 5) hints.push('string.char encoding');
  if (/load(?:string)?\s*\(\s*["']/.test(code)) hints.push('loadstring wrapper');
  if ((code.match(/bit32\.(bxor|band|bor)/g) || []).length > 5) hints.push('bitwise obfuscation');
  if (/while\s+true\s+do[\s\S]{0,200}if\s+\w+\s*==\s*\d+\s+then/.test(code)) hints.push('VM-style dispatcher');
  if ((code.match(/_0x[0-9a-f]{4,}/gi) || []).length > 10) hints.push('hex-mangled identifiers');
  return hints;
}

// ==================== WEAREDEVS DEDICATED UNPACKER ====================

function unpackWeAreDevs(code) {
  const result = {
    detected: false, decoded: null, strings: [], error: null,
    stats: { totalStrings: 0, base64Decoded: 0, payloadSize: 0 },
  };
  if (!/wearedevs\.net\/obfuscator/i.test(code) && !/--\[\[\s*v\d+\.\d+\.\d+\s+https?:\/\/wearedevs/i.test(code)) {
    result.error = 'Not a WeAreDevs script'; return result;
  }
  result.detected = true;

  // pull all string literals (decoded) in source order
  const tokens = lex(code);
  const strings = [];
  for (const t of tokens) {
    if (t.t === TOK.STR) strings.push(decodeStrEscapes(t.body));
    else if (t.t === TOK.LSTR) strings.push(t.body);
  }
  result.stats.totalStrings = strings.length;

  // try base64-decoding everything that looks like base64
  const decoded = strings.map(s => {
    if (/^[A-Za-z0-9+/]+=*$/.test(s) && s.length % 4 === 0 && s.length >= 4) {
      try {
        const d = Buffer.from(s, 'base64').toString('utf-8');
        if (printableScore(d) > 0.85) { result.stats.base64Decoded++; return d; }
      } catch { /* */ }
    }
    return s;
  }).filter(s => s.length >= 4);

  // assemble candidate payloads: try (a) concatenation of all, (b) longest single
  const candidates = [
    decoded.join(''),
    decoded.join('\n'),
    decoded.slice().sort((a, b) => b.length - a.length)[0] || '',
  ];

  for (const c of candidates) {
    if (looksLikeLua(c)) {
      const r = runPipeline(c);
      result.decoded = r.code;
      result.stats.payloadSize = c.length;
      return result;
    }
  }

  result.error = 'Could not reconstruct payload — returning decoded chunks';
  result.strings = decoded;
  return result;
}

// ==================== SANDBOX ====================

function sandboxExecute(code) {
  if (!fengari) return { available: false, captured: [], error: 'fengari not installed' };

  const captured = [];
  const { lua, lauxlib, lualib, to_luastring } = fengari;
  const L = lauxlib.luaL_newstate();
  lualib.luaL_openlibs(L);

  // Hook load/loadstring: capture chunk text AND execute the chunk so payloads run.
  const hookLoad = (L2) => {
    if (lua.lua_isstring(L2, 1)) {
      const s = lua.lua_tojsstring(L2, 1);
      if (s && s.length > 5) captured.push({ type: 'load', value: s });
      // Compile and push real function so caller can invoke payload normally.
      const status = lauxlib.luaL_loadstring(L2, to_luastring(s));
      if (status !== lua.LUA_OK) {
        lua.lua_pop(L2, 1);
        lua.lua_pushjsfunction(L2, () => 0);
      }
    } else {
      lua.lua_pushjsfunction(L2, () => 0);
    }
    return 1;
  };
  lua.lua_pushjsfunction(L, hookLoad); lua.lua_setglobal(L, to_luastring('loadstring'));
  lua.lua_pushjsfunction(L, hookLoad); lua.lua_setglobal(L, to_luastring('load'));

  // Strip dangerous globals
  for (const name of ['os', 'io', 'require', 'dofile', 'loadfile', 'package', 'debug']) {
    lua.lua_pushnil(L); lua.lua_setglobal(L, to_luastring(name));
  }

  // Capture print
  lua.lua_pushjsfunction(L, (L2) => {
    const n = lua.lua_gettop(L2);
    const parts = [];
    for (let i = 1; i <= n; i++) {
      if (lua.lua_isstring(L2, i)) parts.push(lua.lua_tojsstring(L2, i));
      else parts.push(String(lua.lua_tonumber(L2, i)));
    }
    captured.push({ type: 'print', value: parts.join('\t') });
    return 0;
  });
  lua.lua_setglobal(L, to_luastring('print'));

  // Fake Roblox globals so scripts don't crash on `game.Players`, etc.
  const fakeGame = `
    local mt
    mt = {
      __index = function() return setmetatable({}, mt) end,
      __call = function() return setmetatable({}, mt) end,
      __newindex = function() end,
      __tostring = function() return "fake" end,
    }
    local fake = function() return setmetatable({}, mt) end
    game, workspace, script = fake(), fake(), fake()
    Players, ReplicatedStorage, RunService, UserInputService = fake(), fake(), fake(), fake()
    wait, spawn, delay, task = function() end, function() end, function() end, fake()
    tick, os = function() return 0 end, { time = function() return 0 end, clock = function() return 0 end, date = function() return "" end }
    Instance = setmetatable({ new = function() return setmetatable({}, mt) end }, mt)
    Color3 = setmetatable({ new = function() return setmetatable({}, mt) end, fromRGB = function() return setmetatable({}, mt) end }, mt)
    Vector3 = setmetatable({ new = function() return setmetatable({}, mt) end }, mt)
    CFrame = setmetatable({ new = function() return setmetatable({}, mt) end }, mt)
    Enum = setmetatable({}, mt)
  `;
  lauxlib.luaL_dostring(L, to_luastring(fakeGame));

  // Instruction-count-based timeout
  const start = Date.now();
  lua.lua_sethook(L, () => {
    if (Date.now() - start > SANDBOX_TIMEOUT_MS) {
      lauxlib.luaL_error(L, to_luastring('sandbox timeout'));
    }
  }, lua.LUA_MASKCOUNT, 100000);

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

// ==================== EXTRACTORS ====================

function extractStrings(code) {
  const found = [];
  for (const t of lex(code)) {
    if (t.t === TOK.STR) {
      const d = decodeStrEscapes(t.body);
      if (d.length >= 4) found.push(d);
    } else if (t.t === TOK.LSTR && t.body.length >= 4) found.push(t.body);
  }
  return [...new Set(found)];
}

function extractURLs(code) {
  const re = /https?:\/\/[^\s"'<>)]+/gi;
  return [...new Set(code.match(re) || [])];
}

function extractLoadstrings(code) {
  const out = [];
  const tokens = lex(code);
  for (let i = 0; i < tokens.length - 3; i++) {
    const t = tokens[i];
    if (t.t !== TOK.ID || (t.v !== 'load' && t.v !== 'loadstring')) continue;
    const lp = nextNonTrivia(tokens, i); if (!lp.tok || lp.tok.v !== '(') continue;
    const arg = nextNonTrivia(tokens, lp.idx); if (!arg.tok) continue;
    if (arg.tok.t === TOK.STR) out.push(decodeStrEscapes(arg.tok.body));
    else if (arg.tok.t === TOK.LSTR) out.push(arg.tok.body);
  }
  return out;
}

// ==================== I/O ====================

async function getSource(interaction) {
  const code = interaction.options.getString('code');
  const file = interaction.options.getAttachment('file');
  const url = interaction.options.getString('url');

  if (file) {
    if (!/\.(lua|luau|txt)$/i.test(file.name || '')) return { error: 'File must be .lua, .luau, or .txt' };
    if (file.size > MAX_BYTES) return { error: `File too large (${(file.size/1024/1024).toFixed(2)} MB)` };
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
    return interaction.editReply({ content: extra + '
