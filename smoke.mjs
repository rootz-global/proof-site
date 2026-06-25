// Smoke test: boot the server, exercise the Signed MCP routes, exit. Run: node proof-site/smoke.mjs
process.env.PORT = process.env.PORT || '3071';
await import('./server.mjs'); // top-level await + listen
const base = 'http://127.0.0.1:' + process.env.PORT;
await new Promise((r) => setTimeout(r, 300));

const demo = await (await fetch(base + '/sign-demo')).json();
const good = await (await fetch(base + '/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(demo) })).json();
const jwks = await (await fetch(base + '/.well-known/mcp-jwks.json')).json();
const bad = JSON.parse(JSON.stringify(demo));
bad.object.content[0].text = 'TAMPERED';
const tamper = await (await fetch(base + '/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(bad) })).json();
const page = await fetch(base + '/signed-mcp');

console.log('GET /sign-demo       envelope algs :', demo.envelope.algs.join(', '));
console.log('POST /verify (good)  valid         :', good.valid, '| algs:', Object.keys(good.algs).join(', '));
console.log('POST /verify (tamper) valid (want F):', tamper.valid, '|', tamper.reasons.join(','));
console.log('GET  /.well-known/mcp-jwks.json     :', jwks.keys.map((k) => k.alg).join(', '));
console.log('GET  /signed-mcp     status         :', page.status);

const ok = good.valid === true && tamper.valid === false && jwks.keys.length >= 2 && page.status === 200;
console.log(ok ? '\nSMOKE OK' : '\nSMOKE FAILED');
process.exit(ok ? 0 : 1);
