'use strict';

const luaparse = require('luaparse');

// ============================================================
// HELPERS
// ============================================================
function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function escapeForLuaString(s) {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    .replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t')
    .replace(/[\x00-\x1f\x7f]/g, (c) => '\\' + c.charCodeAt(0));
}

function unescapeLua(s) {
  return s.replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\(\d{1,3})/g, (_, d) => String.fromCharCode(parseInt(d, 10)))
    .replace(/\\(["'\\])/g, '$1');
}

const LUA_KEYWORDS = new Set(['and','break','do','else','elseif','end','false','for','function','goto','if','in','local','nil','not','or','repeat','return','then','true','until','while']);
const LUA_GLOBALS = new Set(['_G','_ENV','self','string','table','math','os','io','bit32','coroutine','debug','game','workspace','script','wait','print','warn','error','pcall','xpcall','tostring','tonumber','type','typeof','pairs','ipairs','next','select','setmetatable','getmetatable','require','loadstring','load']);

// ============================================================
// STRING-AWARE WALKER
// ============================================================
function transformStringLiterals(code, transform) {
  let out = '', i = 0, inStr = null, buf = '', quote = '';
  while (i < code.length) {
    const c = code[i];
    if (inStr) {
      if (c === '\\' && i + 1 < code.length) { buf += c + code[i + 1]; i += 2; continue; }
      if (c === inStr) { out += quote + transform(buf) + quote; inStr = null; buf = ''; quote = ''; i++; continue; }
      buf += c; i++; continue;
    }
    if (c === '"' || c === "'") { inStr = c; quote = c; i++; continue; }
    out += c; i++;
  }
  if (inStr) out += quote + buf;
  return out;
}

function protectStrings(code) {
  const placeholders = [];
  const protectedCode = transformStringLiterals(code, (body) => {
    const idx = placeholders.length;
    placeholders.push(body);
    return `\x00STR${idx}\x00`;
  });
  return { code: protectedCode, placeholders };
}

function restoreStrings(code, placeholders) {
  return code.replace(/\x00STR(\d+)\x00/g, (_, i) => placeholders[parseInt(i, 10)] || '');
}

// ============================================================
// NORMALIZE
// ============================================================
function normalize(code) {
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
  return out.replace(/\r\n/g, '\n');
}

// ============================================================
// DECODE
// ============================================================
function decodeHexEscapes(code) {
  return transformStringLiterals(code, (b) =>
    b.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) =>
      escapeForLuaString(String.fromCharCode(parseInt(h, 16)))));
}

function decodeDecimalEscapes(code) {
  return transformStringLiterals(code, (b) =>
    b.replace(/\\(\d{1,3})/g, (m, d) => {
      const n = parseInt(d, 10); if (n > 255) return m;
      return escapeForLuaString(String.fromCharCode(n));
    }));
}

function decodeStringChar(code) {
  let prev, iter = 0;
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
        return `"${escapeForLuaString(chars.join(''))}"`;
      } catch { return m; }
    });
    if (++iter > 20) break;
  } while (code !== prev);
  return code;
}

function decodeStringByte(code) {
  return code.replace(/string\.byte\s*\(\s*(["'])(.)\1\s*(?:,\s*\d+\s*)?\)/g,
    (_, q, ch) => String(ch.charCodeAt(0)));
}

function decodeBase64Blobs(code) {
  return transformStringLiterals(code, (b) => {
    if (b.length < 40 || b.length % 4 !== 0) return b;
    if (!/^[A-Za-z0-9+/]+=*$/.test(b)) return b;
    try {
      const d = Buffer.from(b, 'base64').toString('utf-8');
      if (/^[\x09\x0a\x0d\x20-\x7e]+$/.test(d) && d.length > 4) return escapeForLuaString(d);
    } catch {}
    return b;
  });
}

// ============================================================
// FOLDING
// ============================================================
function foldStringConcat(code) {
  let prev, iter = 0;
  do {
    prev = code;
    code = code.replace(/(["'])((?:\\.|(?!\1)[^\\])*)\1\s*\.\.\s*(["'])((?:\\.|(?!\3)[^\\])*)\3/g,
      (_, q1, a, q2, b) => `"${escapeForLuaString(unescapeLua(a) + unescapeLua(b))}"`);
    if (++iter > 20) break;
  } while (code !== prev);
  return code;
}

function foldArithmetic(code) {
  let prev, iter = 0;
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
    if (++iter > 20) break;
  } while (code !== prev);
  return code;
}

function foldBit32Operations(code) {
  const ops = {
    bxor: (...a) => a.reduce((x, y) => (x ^ y) >>> 0),
    band: (...a) => a.reduce((x, y) => (x & y) >>> 0),
    bor:  (...a) => a.reduce((x, y) => (x | y) >>> 0),
    bnot: (a) => (~a) >>> 0,
    lshift: (a, b) => (a << b) >>> 0,
    rshift: (a, b) => (a >>> b),
    arshift: (a, b) => (a >> b) >>> 0,
  };
  let prev, iter = 0;
  do {
    prev = code;
    code = code.replace(/bit32\.(\w+)\s*\(([^()]+)\)/g, (m, op, args) => {
      const fn = ops[op]; if (!fn) return m;
      const parts = args.split(',').map(s => s.trim());
      if (!parts.every(p => /^-?\d+$/.test(p))) return m;
      try { return String(fn(...parts.map(p => parseInt(p, 10) >>> 0))); }
      catch { return m; }
    });
    if (++iter > 20) break;
  } while (code !== prev);
  return code;
}

// ============================================================
// CONSTANT TABLES
// ============================================================
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
    if (c === '{' || c === '(' || c === '[') depth++;
    else if (c === '}' || c === ')' || c === ']') depth--;
    if (c === ',' && depth === 0) { out.push(buf); buf = ''; continue; }
    buf += c;
  }
  if (buf.trim()) out.push(buf);
  return out;
}

function resolveConstantTableLookups(code) {
  const tables = new Map();
  const re = /local\s+(\w+)\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}/g;
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(code)) !== null) {
    const name = m[1];
    const items = splitTopLevelCommas(m[2]).map(s => s.trim()).filter(Boolean);
    if (items.length < 3) continue;
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
    if (ok && lits.length >= 3) tables.set(name, lits);
  }
  for (const [name, lits] of tables) {
    const idxRe = new RegExp(`\\b${escapeRegex(name)}\\s*\\[\\s*(\\d+)\\s*\\]`, 'g');
    code = code.replace(idxRe, (full, idx) => {
      const i = parseInt(idx, 10) - 1;
      if (i < 0 || i >= lits.length) return full;
      const l = lits[i];
      return l.k === 's' ? `${l.q}${l.v}${l.q}` : l.v;
    });
  }
  return code;
}

// ============================================================
// UNIVERSAL DECRYPTION (memory-efficient)
// ============================================================
function tryAllDecryptions(body) {
  if (body.length < 20 || body.length > 5000) return null;
  const buf = Buffer.from(body, 'binary');
  let best = null;
  for (let k = 1; k < 256; k++) {
    let printable = 0;
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
      const x = buf[i] ^ k;
      out[i] = x;
      if (x === 9 || x === 10 || x === 13 || (x >= 32 && x <= 126)) printable++;
    }
    const s = printable / buf.length;
    if (s > 0.97 && (!best || s > best.s)) {
      best = { m: `xor:${k}`, d: out.toString('binary'), s };
    }
  }
  for (let o = 1; o < 128; o++) {
    let printable = 0, hasAlpha = false;
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
      const x = (buf[i] - o + 256) % 256;
      out[i] = x;
      if (x === 9 || x === 10 || x === 13 || (x >= 32 && x <= 126)) printable++;
      if ((x >= 65 && x <= 90) || (x >= 97 && x <= 122)) hasAlpha = true;
    }
    const s = printable / buf.length;
    if (s > 0.97 && hasAlpha && (!best || s > best.s)) {
      best = { m: `sub:${o}`, d: out.toString('binary'), s };
    }
  }
  return best;
}

function applyUniversalStringDecryption(code) {
  let count = 0, method = null;
  const result = transformStringLiterals(code, (b) => {
    if (b.length < 30) return b;
    const r = tryAllDecryptions(b);
    if (r) { count++; method = method || r.m; return escapeForLuaString(r.d); }
    return b;
  });
  return { code: result, count, method };
}

// ============================================================
// LOADSTRING UNWRAP
// ============================================================
function unwrapAllLoadstringLayers(code, max = 8) {
  let layers = 0;
  for (let i = 0; i < max; i++) {
    const before = code;
    code = decodeHexEscapes(code);
    code = decodeDecimalEscapes(code);
    code = decodeStringChar(code);
    code = foldStringConcat(code);
    const m = code.match(/load(?:string)?\s*\(\s*(["'])([\s\S]+?)\1\s*\)\s*\(\s*\)/);
    if (!m) break;
    const inner = decodeHexEscapes(decodeDecimalEscapes(m[2]));
    if (inner === m[2] || inner.length < 10) break;
    code = code.replace(m[0], inner);
    layers++;
    if (code === before) break;
  }
  return { code, layers };
}

// ============================================================
// SEMANTIC NAMING (string-safe)
// ============================================================
function applySemanticNaming(code) {
  const renames = new Map();
  const patterns = [
    { re: /\b(\w+)\s*:\s*FireServer\s*\(/g, suffix: 'remote' },
    { re: /\b(\w+)\s*:\s*InvokeServer\s*\(/g, suffix: 'remoteFn' },
    { re: /\b(\w+)\s*:\s*Connect\s*\(/g, suffix: 'event' },
    { re: /\b(\w+)\.Character\.Humanoid\b/g, suffix: 'player' },
    { re: /\b(\w+):GetService\s*\(/g, suffix: 'game' },
    { re: /\b(\w+):RequestAsync\s*\(/g, suffix: 'httpService' },
    { re: /\b(\w+):FindFirstChild\s*\(/g, suffix: 'parent' },
  ];
  for (const p of patterns) {
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(code)) !== null) {
      const name = m[1];
      if (LUA_KEYWORDS.has(name) || LUA_GLOBALS.has(name)) continue;
      if (name.length <= 2) continue;
      if (/^[a-z]{2,}/.test(name)) continue;
      if (!renames.has(name)) renames.set(name, `${p.suffix}_guess`);
    }
  }
  if (renames.size === 0) return { code, count: 0 };
  const { code: protectedCode, placeholders } = protectStrings(code);
  let renamed = protectedCode;
  const keys = [...renames.keys()].sort((a, b) => b.length - a.length);
  for (const k of keys) {
    renamed = renamed.replace(new RegExp(`\\b${escapeRegex(k)}\\b`, 'g'), renames.get(k));
  }
  return { code: restoreStrings(renamed, placeholders), count: renames.size };
}

// ============================================================
// IDENTIFIER RENAMING (string-safe)
// ============================================================
function renameIdentifiers(code) {
  let ast;
  try { ast = luaparse.parse(code, { luaVersion: '5.1', comments: false, scope: false }); }
  catch { return code; }

  const seen = new Set();
  const mapping = new Map();
  let counter = 0;
  const isUgly = (n) => !LUA_KEYWORDS.has(n) && !LUA_GLOBALS.has(n) &&
    (/^_*[ilI1O0]{4,}_*$/.test(n) || n.length > 24 || /^[A-Z_]{10,}$/.test(n));
  const visit = (node) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach(visit); return; }
    if (node.type === 'Identifier' && node.name && !seen.has(node.name) && isUgly(node.name)) {
      seen.add(node.name);
      mapping.set(node.name, `v${++counter}`);
    }
    for (const k of Object.keys(node)) if (k !== 'type') visit(node[k]);
  };
  visit(ast);
  if (mapping.size === 0) return code;

  const { code: protectedCode, placeholders } = protectStrings(code);
  let renamed = protectedCode;
  const keys = [...mapping.keys()].sort((a, b) => b.length - a.length);
  for (const k of keys) {
    renamed = renamed.replace(new RegExp(`\\b${escapeRegex(k)}\\b`, 'g'), mapping.get(k));
  }
  return restoreStrings(renamed, placeholders);
}

// ============================================================
// DEAD CODE + BEAUTIFY
// ============================================================
function removeDeadCode(code) {
  code = code.replace(/\bif\s+false\s+then\b[\s\S]*?\bend\b/g, '');
  code = code.replace(/\bwhile\s+false\s+do\b[\s\S]*?\bend\b/g, '');
  code = code.replace(/\bdo\s+end\b/g, '');
  return code.replace(/\n{3,}/g, '\n\n');
}

function beautify(code) {
  // String-aware preprocessing: only split on ; outside strings
  let processed = '', i = 0, inStr = null;
  while (i < code.length) {
    const c = code[i];
    if (inStr) {
      if (c === '\\') { processed += c + (code[i+1] || ''); i += 2; continue; }
      if (c === inStr) inStr = null;
      processed += c; i++; continue;
    }
    if (c === '"' || c === "'") { inStr = c; processed += c; i++; continue; }
    if (c === ';') { processed += '\n'; i++; continue; }
    processed += c; i++;
  }
  const lines = processed.split('\n').map(l => l.trim()).filter(Boolean);
  const result = [];
  let indent = 0;
  for (const l of lines) {
    if (/^(end\b|else\b|elseif\b|until\b)/.test(l)) indent = Math.max(0, indent - 1);
    result.push('  '.repeat(indent) + l);
    if (/(\bthen|\bdo|\bfunction\b[^)]*\)|\brepeat|\belse)\s*$/.test(l)) indent++;
    if (/^(else|elseif)\b/.test(l)) indent++;
  }
  return result.join('\n') + '\n';
}

// ============================================================
// VM ANALYZER
// ============================================================
function analyzeCustomVM(code) {
  const a = { detected: false, dispatcherType: null, opcodeCount: 0, opcodes: [], constantPoolSize: 0, bytecodeSize: 0 };
  const jumpRe = /\[(\d+)\]\s*=\s*function\s*\(([^)]*)\)([\s\S]*?)end/g;
  jumpRe.lastIndex = 0;
  const jumps = [...code.matchAll(jumpRe)];
  if (jumps.length >= 5) {
    a.detected = true;
    a.dispatcherType = 'jump_table';
    a.opcodeCount = jumps.length;
    for (const m of jumps.slice(0, 30)) {
      a.opcodes.push({ op: parseInt(m[1], 10), bodySize: m[3].length, guess: guessOpcodeKind(m[3]) });
    }
  }
  if (!a.detected) {
    const disp = code.match(/while\s+true\s+do([\s\S]*?)end\s*end/);
    if (disp && /if\s+\w+\s*==\s*\d+/.test(disp[1])) {
      const ifRe = /(?:if|elseif)\s+\w+\s*==\s*(\d+)\s+then([\s\S]*?)(?=elseif|else\b|end)/g;
      ifRe.lastIndex = 0;
      const ops = [...disp[1].matchAll(ifRe)];
      if (ops.length >= 5) {
        a.detected = true;
        a.dispatcherType = 'if_elseif_chain';
        a.opcodeCount = ops.length;
        for (const m of ops.slice(0, 30)) {
          a.opcodes.push({ op: parseInt(m[1], 10), bodySize: m[2].length, guess: guessOpcodeKind(m[2]) });
        }
      }
    }
  }
  const pool = code.match(/local\s+\w+\s*=\s*\{([^{}]{200,})\}/);
  if (pool) a.constantPoolSize = pool[1].split(',').length;
  let biggest = '';
  const strRe = /(["'])((?:\\.|(?!\1).)*)\1/g;
  strRe.lastIndex = 0;
  let m;
  while ((m = strRe.exec(code)) !== null) if (m[2].length > biggest.length) biggest = m[2];
  if (biggest.length > 500) a.bytecodeSize = biggest.length;
  return a;
}

function guessOpcodeKind(b) {
  if (/\[\w+\]\s*=\s*\[\w+\]/.test(b) && b.length < 80) return 'MOVE';
  if (/\[\w+\]\s*=\s*[\w.]+\[\w+\]/.test(b)) return 'GETTABLE/LOADK';
  if (/\+/.test(b) && /\[\w+\]/.test(b)) return 'ADD';
  if (/-/.test(b) && /\[\w+\]/.test(b)) return 'SUB';
  if (/\*/.test(b) && /\[\w+\]/.test(b)) return 'MUL';
  if (/\//.test(b) && /\[\w+\]/.test(b)) return '
