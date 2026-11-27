import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
const stateDirectory = path.resolve(process.argv[2] || '../adspower-private-state');
const repository = path.dirname(fileURLToPath(import.meta.url));
const relative = path.relative(path.resolve(repository), stateDirectory);
if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
  throw new Error('State directory must be outside the repository');
}
await fs.mkdir(stateDirectory, { recursive: true });
const sessions = new Map();
const page = `<!doctype html><meta charset="utf-8"><title>Local browser audit</title>
<h1>本地浏览器检查</h1><p>仅在本机收集浏览器特征。填写环境编号，然后运行。再次运行同一环境可检查存储是否保留。</p>
<label>环境编号 <input id="profile" required maxlength="64"></label>
<button id="run">运行检查</button><pre id="result"></pre>
<script>
const storageKey = 'adspower-audit-v1';
async function run() {
  const profile = document.querySelector('#profile').value.trim();
  if (!profile) return;
  const output = document.querySelector('#result');
  try {
    const previous = localStorage.getItem(storageKey);
    const marker = previous || crypto.randomUUID();
    localStorage.setItem(storageKey, marker);
    let hints = { status: 'unsupported' };
    if (navigator.userAgentData) {
      try {
        hints = await navigator.userAgentData.getHighEntropyValues(['architecture', 'bitness', 'platform', 'platformVersion', 'fullVersionList', 'model']);
      } catch (error) { hints = { status: 'error', message: error.message }; }
    }
    const canvas = document.createElement('canvas');
    canvas.width = 320; canvas.height = 80;
    const ctx = canvas.getContext('2d');
    let canvasHash = null;
    if (ctx) {
      ctx.font = '18px sans-serif'; ctx.fillText('Browser audit 中文 é 😀', 4, 30);
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canvas.toDataURL()));
      canvasHash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
    }
    const gl = document.createElement('canvas').getContext('webgl');
    const extension = gl && gl.getExtension('WEBGL_debug_renderer_info');
    const webgl = extension ? { vendor: gl.getParameter(extension.UNMASKED_VENDOR_WEBGL), renderer: gl.getParameter(extension.UNMASKED_RENDERER_WEBGL) } : { status: 'unavailable' };
    let webgpu = { status: 'unsupported' };
    if (navigator.gpu) {
      try {
        const adapter = await navigator.gpu.requestAdapter();
        webgpu = adapter ? { status: 'available', info: adapter.info ? { vendor: adapter.info.vendor, architecture: adapter.info.architecture, device: adapter.info.device, description: adapter.info.description } : null } : { status: 'no-adapter' };
      } catch (error) { webgpu = { status: 'error', message: error.message }; }
    }
    const report = {
      profile, capturedAt: new Date().toISOString(), userAgent: navigator.userAgent,
      platform: navigator.platform, clientHints: hints,
      hardwareConcurrency: navigator.hardwareConcurrency, deviceMemory: navigator.deviceMemory ?? null,
      screen: { width: screen.width, height: screen.height, availableWidth: screen.availWidth, availableHeight: screen.availHeight, dpr: devicePixelRatio, colorDepth: screen.colorDepth },
      languages: navigator.languages, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      canvasHash, webgl, webgpu,
      storage: { marker, previous, stored: localStorage.getItem(storageKey) === marker },
      rtcApiPresent: typeof RTCPeerConnection !== 'undefined',
      unverified: ['TLS', 'HTTP/2', 'public IP', 'complete fonts', 'WebRTC network behavior', 'IndexedDB isolation', 'ServiceWorker isolation', 'actual OS', 'browser full build outside reported values']
    };
    const response = await fetch('/report', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(report) });
    const saved = await response.json();
    if (!response.ok) throw new Error(saved.error);
    output.textContent = JSON.stringify(saved, null, 2);
  } catch (error) { output.textContent = error.message; }
}
document.querySelector('#run').onclick = run;
</script>`;
const server = http.createServer(async (request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  const host = request.headers.host;
  if (host !== '127.0.0.1:8765') {
    response.writeHead(403).end(); return;
  }
  if (request.method === 'GET' && request.url === '/') {
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, Date.now());
    response.setHeader('Set-Cookie', 'audit_session=' + token + '; HttpOnly; SameSite=Strict; Path=/');
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    response.end(page); return;
  }
  if (request.method !== 'POST' || request.url !== '/report') {
    response.writeHead(404).end(); return;
  }
  const token = /(?:^|;\s*)audit_session=([a-f0-9]+)/.exec(request.headers.cookie || '')?.[1];
  if (request.headers.origin !== 'http://127.0.0.1:8765' || !sessions.has(token)) {
    response.writeHead(403).end(); return;
  }
  let body = '';
  try {
    for await (const chunk of request) {
      body += chunk;
      if (body.length > 65536) throw new Error('Report too large');
    }
    const report = JSON.parse(body);
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(report.profile || '')) throw new Error('Use a numeric ID or ASCII profile ID');
    if (!report.storage || typeof report.storage.marker !== 'string') throw new Error('Missing storage observation');
    // Each report is immutable. Concurrent submissions never overwrite one another.
    const filename = crypto.randomUUID() + '.json';
    const record = { schemaVersion: 1, receivedAt: new Date().toISOString(), stage: 'browser_observed', requestHints: Object.fromEntries(Object.entries(request.headers).filter(([key]) => key.startsWith('sec-ch-ua') || key === 'user-agent')), report };
    await fs.writeFile(path.join(stateDirectory, filename), JSON.stringify(record, null, 2), { flag: 'wx' });
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify({ saved: filename, stage: record.stage, report }));
  } catch (error) {
    response.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: error.message }));
  }
});
server.listen(8765, '127.0.0.1', () => console.log('Audit listening at http://127.0.0.1:8765/'));
