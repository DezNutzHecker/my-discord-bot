'use strict';

const {
  Client, GatewayIntentBits, REST, Routes,
  SlashCommandBuilder, AttachmentBuilder, EmbedBuilder,
  Events, MessageFlags,
} = require('discord.js');
require('dotenv').config();

const { DISCORD_TOKEN, CLIENT_ID, GUILD_ID } = process.env;
if (!DISCORD_TOKEN || !CLIENT_ID) {
  console.error('Missing DISCORD_TOKEN or CLIENT_ID in .env');
  process.exit(1);
}

const MAX_BYTES = 5_000_000;
const MAX_INLINE = 1900;

// ==================== HELPERS ====================

function escapeLua(s) {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    .replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t')
    .replace(/[\x00-\x1f\x7f]/g, c => '\\' + c.charCodeAt(0));
}

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

// ==================== DECODERS ====================

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
  return walkStrings(code, b => {
    if (b.length < 16 || b.length % 4 !== 0) return b;
    if (!/^[A-Za-z0-9+/]+=*$/.test(b)) return b;
    try {
      const decoded = Buffer.from(b, 'base64').toString('utf-8');
      if (printableScore(decoded) > 0.9 && decoded.length > 4) {
        return escapeLua(decoded);
      }
    } catch {}
    return b;
  });
}

function bruteXorStrings(code) {
  let count = 0;
  const result = walkStrings(code, b => {
    if (b.length < 20 || b.length > 5000) return b;
    if (printableScore(b) > 0.9) return b; // already readable
    let best = null;
    for (let k = 1; k < 256; k++) {
      const decoded = [...b].map(c => String.fromCharCode(c.charCodeAt(0) ^ k)).join('');
      const score = printableScore(decoded);
      if (score > 0.95 && /[a-zA-Z]{3,}/.test(decoded)) {
        if (!best || score > best.score) best = { decoded, score, k };
      }
    }
    if (best) { count++; return escapeLua(best.decoded); }
    return b;
  });
  return { code: result, count };
}

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
    bxor: (a, b) => (a ^ b) >>> 0,
    band: (a, b) => (a & b) >>> 0,
    bor: (a, b) => (a | b) >>> 0,
    bnot: a => (~a) >>> 0,
    lshift: (a, b) => (a << b) >>> 0,
    rshift: (a, b) => (a >>> b),
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

function resolveConstantTables(code) {
  const tables = new Map();
  const re = /local\s+(\w+)\s*=\s*\{([^{}]+)\}/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const name = m[1];
    const items = m[2].split(',').map(s => s.trim()).filter(Boolean);
    if (items.length < 3) continue;
    const lits = []; let ok = true;
    for (const it of items) {
      const sm = it.match(/^(["'])((?:\\.|(?!\1)[^\\])*)\1$/);
      const nm = it.match(/^-?\d+(?:\.\d+)?$/);
      if (sm) lits.push({ k: 's', v: sm[2], q: sm[1] });
      else if (nm) lits.push({ k: 'n', v: it });
      else { ok = false; break; }
    }
    if (ok && lits.length >= 3) tables.set(name, lits);
  }
  for (const [name, lits] of tables) {
    const escName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    code = code.replace(new RegExp(`\\b${escName}\\s*\\[\\s*(\\d+)\\s*\\]`, 'g'), (full, idx) => {
      const i = parseInt(idx, 10) - 1;
      if (i < 0 || i >= lits.length) return full;
      const l = lits[i];
      return l.k === 's' ? `${l.q}${l.v}${l.q}` : l.v;
    });
  }
  return code;
}

function unwrapLoadstrings(code, max = 8) {
  let layers = 0;
  for (let i = 0; i < max; i++) {
    const m = code.match(/load(?:string)?\s*\(\s*(["'])([\s\S]+?)\1\s*\)\s*\(\s*\)/);
    if (!m) break;
    const inner = decodeHex(decodeDecimal(m[2]));
    if (inner === m[2] || inner.length < 5) break;
    code = code.replace(m[0], inner);
    layers++;
  }
  return { code, layers };
}

function removeDeadCode(code) {
  code = code.replace(/\bif\s+false\s+then\b[\s\S]*?\bend\b/g, '');
  code = code.replace(/\bwhile\s+false\s+do\b[\s\S]*?\bend\b/g, '');
  code = code.replace(/\bdo\s+end\b/g, '');
  return code.replace(/\n{3,}/g, '\n\n');
}

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
  if (buf) tokens.push({ s: !!inStr, v: buf });

  let joined = '';
  for (const t of tokens) {
    if (t.s) joined += t.v;
    else {
      let v = t.v.replace(/;/g, '\n');
      v = v.replace(/\b(then|do)\b/g, '$1\n');
      v = v.replace(/\b(end|else|elseif|until)\b/g, '\n$1');
      joined += v;
    }
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

// ==================== FINGERPRINTING ====================

function detectObfuscator(code) {
  const hints = [];
  if (/Luraph|LPH_/i.test(code)) hints.push('Luraph');
  if (/Moonsec|MoonSec/i.test(code)) hints.push('Moonsec');
  if (/Ironbrew|IronBrew/i.test(code)) hints.push('IronBrew');
  if (/Prometheus/i.test(code)) hints.push('Prometheus');
  if (/Wynfuscate/i.test(code)) hints.push('Wynfuscate');
  if (/WeAreDevs/i.test(code)) hints.push('WeAreDevs');
  if (/SynapseXen|Synapse Xen/i.test(code)) hints.push('Synapse Xen');
  if (/\\x[0-9a-f]{2}/i.test(code) && code.length > 1000) hints.push('hex-encoded strings');
  if (/string\.char\s*\(\s*\d+/.test(code)) hints.push('string.char encoding');
  if (/load(?:string)?\s*\(\s*["']/.test(code)) hints.push('loadstring wrapper');
  if (/bit32\.(bxor|band|bor)/.test(code)) hints.push('bitwise obfuscation');
  return hints;
}

// ==================== PIPELINE ====================

function decodeFull(code) {
  const stats = { passes: 0, layers: 0, xorDecoded: 0, originalSize: code.length };
  code = stripComments(code);

  let prev;
  do {
    prev = code;
    code = decodeHex(code);
    code = decodeDecimal(code);
    code = decodeStringChar(code);
    code = decodeBase64Strings(code);
    code = foldConcat(code);
    code = foldArithmetic(code);
    code = foldBit32(code);
    code = resolveConstantTables(code);
    const unwrap = unwrapLoadstrings(code);
    code = unwrap.code;
    stats.layers += unwrap.layers;
    stats.passes++;
  } while (code !== prev && stats.passes < 10);

  const xorResult = bruteXorStrings(code);
  code = xorResult.code;
  stats.xorDecoded = xorResult.count;

  code = removeDeadCode(code);
  code = beautify(code);
  stats.finalSize = code.length;
  return { code, stats };
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
    if (file.size > MAX_BYTES) return { error: `File too large (${(file.size/1024/1024).toFixed(1)} MB, max ${MAX_BYTES/1024/1024} MB)` };
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
  const client = new Client({ intents:
