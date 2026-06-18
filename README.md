# Lua Deobfuscator Bot

A Discord bot for deobfuscating Roblox Lua scripts. Supports 50+ obfuscators with autocomplete engine selection, multi-pass convergence, AST analysis, custom VM detection, and universal string decryption.

## Commands

- `/help` — Show command list
- `/cfg` — Toggle Hook OP and Debug Dumper settings
- `/env` — Dump script/environment as `.log` file
- `/get` — Fetch raw source as `.lua` file
- `/deobf` — Deobfuscate with engine autocomplete (50+ engines)
- `/beautify` — Beautify Lua/txt source
- `/extract` — Extract loadstrings, strings, URLs, constants, remotes
- `/cascade` — Run multiple engines and return the best result
- `/whitelist`, `/unwhitelist`, `/whitelisted` — Owner-only user management

## Setup

```bash
git clone <your-repo-url>
cd your-bot
npm install
cp .env.example .env
# Edit .env with your Discord token, client ID, and owner ID
npm run register   # one-time slash command registration
npm start
```

## Requirements

- Node.js 18 or newer
- ~256-512 MB RAM (configurable via WORKER_POOL_SIZE / WORKER_MEMORY_MB)
- A Discord bot token from https://discord.com/developers/applications

## Hosting

Works on any always-on Node 18+ environment. Tested options:
- Local machine via `pm2`
- Android device via Termux
- Any VPS

## Honest scope

This tool produces near-original output for: plain Lua, minified code, LuaObfuscator.com, WeAreDevs, Prometheus. Partial recovery for: Ironbrew v1, older Moonsec. Surface-level decoding only for: Luraph, Ironbrew v2, modern Moonsec, and other VM-protected obfuscators — no public tool fully lifts these.

## License

MIT
File 5: deobf-worker.js
'use strict';

const { parentPort } = require('node:worker_threads');
const { deobfuscate } = require('./vortex-ultimate.js');

process.on('uncaughtException', (err) => {
  try { parentPort.postMessage({ ok: false, error: `Worker crashed: ${err.message}` }); } catch {}
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  try { parentPort.postMessage({ ok: false, error: `Worker rejected: ${err?.message || err}` }); } catch {}
  process.exit(1);
});

parentPort.on('message', (msg) => {
  try {
    const result = deobfuscate(msg.code, msg.engine);
    parentPort.postMessage({ ok: true, result });
  } catch (err) {
    parentPort.postMessage({ ok: false, error: err.message });
  }
});
