'use strict';

function decodeEscapes(s) {
  return s
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\(\d{1,3})/g, (_, d) => String.fromCharCode(parseInt(d, 10)))
    .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\(["'\\])/g, '$1');
}

function splitTopLevelCommas(s) {
  const out = [];
  let depth = 0, buf = '', inStr = null;
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

function extractLoadstringPayloads(code) {
  const payloads = [];
  const re = /load(?:string)?\s*\(\s*(["'])([\s\S]*?)\1\s*\)/g;
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(code)) !== null) {
    payloads.push({
      raw: m[0].length > 80 ? m[0].slice(0, 80) + '...' : m[0],
      payload: decodeEscapes(m[2]),
      index: m.index,
    });
  }
  return payloads;
}

function extractStrings(code) {
  const strings = new Set();
  const re = /(["'])((?:\\.|(?!\1).)*)\1/g;
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(code)) !== null) {
    const s = decodeEscapes(m[2]);
    if (s.length >= 3 && s.length <= 500) strings.add(s);
  }
  return [...strings];
}

function extractURLs(code) {
  const urls = new Set();
  const re = /https?:\/\/[^\s"'<>,)]+[^\s"'<>,.)]/g;
  re.lastIndex = 0;
  for (const match of code.matchAll(re)) urls.add(match[0]);
  for (const s of extractStrings(code)) {
    for (const match of s.matchAll(re)) urls.add(match[0]);
  }
  return [...urls];
}

function extractConstantTables(code) {
  const tables = [];
  const re = /local\s+(\w+)\s*=\s*\{([^{}]{40,})\}/g;
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(code)) !== null) {
    const items = splitTopLevelCommas(m[2]).map(s => s.trim()).filter(Boolean);
    if (items.length < 3) continue;
    const literals = items.every(i => /^(["'].*["']|-?\d+(?:\.\d+)?|true|false|nil)$/.test(i));
    if (literals) tables.push({ name: m[1], size: items.length, sample: items.slice(0, 10) });
  }
  return tables;
}

function extractRemoteCalls(code) {
  const calls = [];
  const re = /(\w+(?:[.:]\w+)*)\s*:\s*(FireServer|FireClient|FireAllClients|InvokeServer|InvokeClient|Fire|Invoke)\s*\(([^)]*)\)/g;
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(code)) !== null) {
    calls.push({ target: m[1], method: m[2], args: m[3].trim() });
  }
  return calls;
}

function extractServices(code) {
  const services = new Set();
  const re = /game\s*:\s*GetService\s*\(\s*(["'])(\w+)\1\s*\)/g;
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(code)) !== null) services.add(m[2]);
  return [...services];
}

function scanSuspicious(code) {
  const flags = [];
  const checks = [
    { name: 'Discord webhook', re: /discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/i, severity: 'high' },
    { name: 'IP logger', re: /ipify\.org|ipapi\.co|ipinfo\.io/i, severity: 'high' },
    { name: 'HttpService POST', re: /HttpService.*Post|RequestAsync.*POST/, severity: 'medium' },
    { name: 'getfenv use', re: /\bgetfenv\s*\(/, severity: 'low' },
    { name: 'setfenv use', re: /\bsetfenv\s*\(/, severity: 'medium' },
    { name: 'loadstring use', re: /\bload(?:string)?\s*\(/, severity: 'low' },
    { name: 'Persistence write', re: /writefile\s*\(|appendfile\s*\(/, severity: 'medium' },
  ];
  for (const c of checks) if (c.re.test(code)) flags.push({ name: c.name, severity: c.severity });
  return flags;
}

function extractAll(code) {
  return {
    loadstrings: extractLoadstringPayloads(code),
    strings: extractStrings(code),
    urls: extractURLs(code),
    constants: extractConstantTables(code),
    remotes: extractRemoteCalls(code),
    services: extractServices(code),
    flags: scanSuspicious(code),
  };
}

module.exports = {
  extractAll, extractLoadstringPayloads, extractStrings, extractURLs,
  extractConstantTables, extractRemoteCalls, extractServices, scanSuspicious,
};
