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

const MAX_BYTES = 500_000;
const MAX_INLINE = 1900;

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

function foldConcat(code) {
  let prev;
  do {
    prev = code;
    code = code.replace(/"((?:\\.|[^"\\])*)"\s*\.\.\s*"((?:\\.|[^"\\])*)"/g,
      (_, a, b) => `"${a}${b}"`);
  } while (code !== prev);
  return code;
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

function decode(code) {
  let prev, passes = 0;
  do {
    prev = code;
    code = decodeHex(code);
    code = decodeDecimal(code);
    code = decodeStringChar(code);
    code = foldConcat(code);
    passes++;
  } while (code !== prev && passes < 5);
  return code;
}

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

async function getSource(interaction) {
  const code = interaction.options.getString('code');
  const file = interaction.options.getAttachment('file');
  const url = interaction.options.getString('url');

  if (file) {
    if (!/\.(lua|luau|txt)$/i.test(file.name || '')) return { error: 'File must be .lua, .luau, or .txt' };
    if (file.size > MAX_BYTES) return { error: `File too large (${(file.size/1024).toFixed(1)} KB)` };
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
  return { error: 'Provide `code`, `file`, or `url`' };
}

async function sendOutput(interaction, content, filename) {
  if (content.length <= MAX_INLINE) {
    return interaction.editReply({ content: '```lua\n' + content + '\n```' });
  }
  const buf = Buffer.from(content, 'utf-8');
  return interaction.editReply({
    content: `📦 Output (${(buf.length/1024).toFixed(1)} KB)`,
    files: [new AttachmentBuilder(buf, { name: filename })],
  });
}

const sourceOpts = b => b
  .addStringOption(o => o.setName('code').setDescription('Paste code').setRequired(false))
  .addAttachmentOption(o => o.setName('file').setDescription('Upload .lua/.luau/.txt').setRequired(false))
  .addStringOption(o => o.setName('url').setDescription('Raw URL').setRequired(false));

const commands = [
  new SlashCommandBuilder().setName('help').setDescription('Show command list'),
  sourceOpts(new SlashCommandBuilder().setName('beautify').setDescription('Clean up Lua formatting')),
  sourceOpts(new SlashCommandBuilder().setName('decode').setDescription('Decode escapes and fold concats')),
  sourceOpts(new SlashCommandBuilder().setName('extract').setDescription('Extract strings, URLs, loadstrings')),
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
            { name: '/decode', value: 'Decode escapes, string.char, fold concats' },
            { name: '/extract', value: 'Pull strings, URLs, and loadstring payloads' },
          )
          .setFooter({ text: 'Each command takes code, file, or url.' });
        return interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral });
      }

      await interaction.deferReply();
      const src = await getSource(interaction);
      if (src.error) return interaction.editReply(src.error);

      if (cmd === 'beautify') {
        const out = beautify(stripComments(src.code));
        return sendOutput(interaction, out, 'beautified.lua');
      }
      if (cmd === 'decode') {
        const out = beautify(decode(stripComments(src.code)));
        return sendOutput(interaction, out, 'decoded.lua');
      }
      if (cmd === 'extract') {
        const stripped = stripComments(src.code);
        const strings = extractStrings(stripped).slice(0, 200);
        const urls = extractURLs(stripped);
        const loads = extractLoadstrings(stripped);
        const report =
          `-- URLs (${urls.length}) --\n${urls.join('\n') || '(none)'}\n\n` +
          `-- Loadstring payloads (${loads.length}) --\n${loads.map((l,i) => `[${i+1}] ${l.slice(0,200)}`).join('\n') || '(none)'}\n\n` +
          `-- Strings (showing ${strings.length}) --\n${strings.map(s => JSON.stringify(s)).join('\n')}`;
        return sendOutput(interaction, report, 'extract.txt');
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

if (process.argv[2] === 'register') {
  registerCommands();
} else {
  startBot();
}
