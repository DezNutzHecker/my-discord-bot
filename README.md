# Lua Bot

A Discord bot for working with Lua scripts. Beautifies messy code, decodes common obfuscation tricks, and extracts useful info like URLs and strings.

## Commands

### `/help`
Shows the command list inside Discord.

### `/beautify`
Cleans up Lua formatting. Adds proper indentation, splits statements onto their own lines, and makes the code readable.

**Use when:** you have minified or single-line Lua you want to read.

### `/decode`
Runs a decoding pass on the script:
- Decodes `\xNN` hex escapes inside strings
- Decodes `\NNN` decimal escapes inside strings
- Evaluates `string.char(72, 105)` into `"Hi"`
- Folds string concatenations like `"foo" .. "bar"` into `"foobar"`
- Runs multiple passes until nothing changes
- Beautifies the result at the end

**Use when:** a script hides strings using char codes or escapes.

### `/extract`
Pulls useful info out of the script and returns a report:
- All URLs (`http://` and `https://`)
- All `loadstring(...)` payloads
- All string literals 4+ characters long (deduplicated, first 200 shown)

**Use when:** you want to see what a script connects to or what data it carries, without reading the whole thing.

## Command inputs

Every command (except `/help`) accepts one of three input methods:

| Option | What it does |
|--------|--------------|
| `code` | Paste Lua directly into the command |
| `file` | Upload a `.lua`, `.luau`, or `.txt` file |
| `url`  | Provide a raw URL the bot will fetch |

Max input size: 500 KB.

## Setup

1. `npm install`
2. Create a `.env` file with `DISCORD_TOKEN`, `CLIENT_ID`, and `GUILD_ID`
3. `node index.js register` — registers the slash commands (run once)
4. `node index.js` — starts the bot

## What this bot does NOT do

- Crack heavy VM-based obfuscators like Luraph v14 or Moonsec v3 — those require dedicated reverse-engineering tools
- Execute Lua code in a sandbox
- Recover original variable names or comments (they're gone once obfuscated)

This is a fast, lightweight toolkit for common cases — not a full deobfuscator suite.
