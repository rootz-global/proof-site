// origin-binder.mjs — Proof of Origin (Pillar 1) binder for proof.rootz.global
// Browser-compatible P-256 data wallet: the customer signs the prompt at the source,
// this binder calls the model and mints a signed, prompt-bound wallet the browser validates.
// Pure WebCrypto (Node 18+ global crypto) + global fetch. No external deps.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
const randHex = (n) => hex(globalThis.crypto.getRandomValues(new Uint8Array(n)));

// Canonicalization MUST match the browser: JSON.stringify over recursively key-sorted object.
const sortDeep = (v) => Array.isArray(v) ? v.map(sortDeep)
  : (v && typeof v === 'object' ? Object.keys(v).sort().reduce((o, k) => (o[k] = sortDeep(v[k]), o), {}) : v);
const canon = (o) => enc.encode(JSON.stringify(sortDeep(o)));
const sha = async (b) => hex(await subtle.digest('SHA-256', b));

async function importPub(h) {
  return subtle.importKey('raw', unhex(h), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

// --- binder identity (persisted P-256 keypair) ---
export class Binder {
  constructor(priv, pubHex) { this.priv = priv; this.pubHex = pubHex; }

  static async load(path) {
    if (path && existsSync(path)) {
      try {
        const j = JSON.parse(readFileSync(path, 'utf-8'));
        const priv = await subtle.importKey('pkcs8', unhex(j.priv_pkcs8), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
        return new Binder(priv, j.pub_raw);
      } catch (e) { /* fall through to fresh */ }
    }
    const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pubHex = hex(await subtle.exportKey('raw', kp.publicKey));
    const privPkcs8 = hex(await subtle.exportKey('pkcs8', kp.privateKey));
    if (path) { try { writeFileSync(path, JSON.stringify({ priv_pkcs8: privPkcs8, pub_raw: pubHex }), { mode: 0o600 }); } catch (e) {} }
    return new Binder(kp.privateKey, pubHex);
  }

  async sign(bytes) { return hex(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.priv, bytes)); }

  async mint(type, body, role) {
    const ev = { type, body, signer_role: role || 'binder', signer_pub: this.pubHex };
    ev.sig = await this.sign(canon(ev));
    return ev;
  }
}

export async function verifyEvent(ev) {
  const sp = { type: ev.type, body: ev.body, signer_role: ev.signer_role, signer_pub: ev.signer_pub };
  try { return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, await importPub(ev.signer_pub), unhex(ev.sig), canon(sp)); }
  catch (e) { return false; }
}

async function leaf(ev) { return sha(canon(ev)); }
async function merkle(leaves) {
  if (!leaves.length) return sha(new Uint8Array());
  let lvl = leaves.map(unhex);
  while (lvl.length > 1) {
    const nx = [];
    for (let i = 0; i < lvl.length; i += 2) {
      const a = lvl[i], b = i + 1 < lvl.length ? lvl[i + 1] : lvl[i];
      const c = new Uint8Array(a.length + b.length); c.set(a); c.set(b, a.length);
      nx.push(new Uint8Array(await subtle.digest('SHA-256', c)));
    }
    lvl = nx;
  }
  return hex(lvl[0]);
}

// --- the model call: real Claude if a key is present, else clearly-labeled mock ---
export async function callModel(prompt) {
  const key = process.env.ANTHROPIC_API_KEY;
  const model = process.env.PROOF_MODEL || 'claude-opus-4-8';
  if (!key || process.env.PROOF_MOCK) {
    return { text: `「mock」 You said: ${String(prompt).slice(0, 280)}\n\n(No API key bound to this binder — this is a labeled mock so the proof pipeline is fully exercised. weight_measured=false either way.)`, model: model + ' (MOCK)', real: false };
  }
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model, max_tokens: 1024, messages: [{ role: 'user', content: String(prompt) }] }),
    });
    const j = await r.json();
    if (!r.ok) return { text: `[model call rejected: ${j?.error?.message || r.status}]`, model: `${model} (error)`, real: false };
    const text = (j.content || []).map((b) => b.text || '').join('') || '[empty response]';
    return { text, model: j.model || model, real: true, request_id: j.id };
  } catch (e) {
    return { text: `[model call failed: ${e.message}]`, model: `${model} (error)`, real: false };
  }
}

// --- the binder pipeline: verify intent -> call model -> mint signed wallet ---
export async function infer(intent, binder) {
  if (!intent || !intent.body) return { error: 'no-intent' };
  if (!(await verifyEvent(intent))) return { error: 'bad-customer-signature' };
  const prompt = intent.body.prompt;
  const ph = intent.body.prompt_hash;
  if (typeof prompt !== 'string') return { error: 'no-prompt' };
  if ((await sha(enc.encode(prompt))) !== ph) return { error: 'prompt-hash-mismatch' };

  const m = await callModel(prompt);
  const outHash = await sha(enc.encode(m.text));

  const events = [
    await binder.mint('processor_attestation', { tee: 'mock', measurement: 'no-hardware-in-this-demo', note: 'swap for TDX/SEV + nvtrust on GCP A3' }, 'processor'),
    await binder.mint('model_identity', {
      model: m.model,
      measurement: {
        method: m.real ? 'api-assertion over authenticated TLS to api.anthropic.com' : 'none (mock — no key bound)',
        verified: m.real ? ['tls:api.anthropic.com', 'response.model', 'request_id'] : [],
        level: m.real ? 'L1 · attested transport' : 'L0 · none (mock)',
        measured_at: new Date().toISOString(),
      },
      weight_measured: false,
      request_id: m.request_id || null,
    }, 'model'),
    await binder.mint('output', { prompt_hash: ph, output_hash: outHash }, 'binder'),
  ];

  const leaves = [await leaf(intent)];
  for (const e of events) leaves.push(await leaf(e));
  const root = await merkle(leaves);

  const wallet = {
    wallet_id: 'w_' + randHex(12),
    genesis: intent,
    events,
    merkle_root: root,
    anchor: { chain: 'mock', tx: '0x' + randHex(32), note: 'demo anchor — real chain anchor is the rollup step' },
    binder_pub: binder.pubHex,
  };
  wallet.sig = await binder.sign(canon(wallet));
  return { output: m.text, real: m.real, wallet };
}

// --- validator (same checks the browser runs) — used by the local test ---
export async function validate(w, binderPubHex) {
  const checks = [];
  const chk = (n, c) => { checks.push([n, !!c]); return !!c; };
  chk('genesis_customer_signature', await verifyEvent(w.genesis));
  const evs = {};
  for (const e of w.events) { evs[e.type] = e; chk('event_sig:' + e.type, await verifyEvent(e)); }
  const ws = { wallet_id: w.wallet_id, genesis: w.genesis, events: w.events, merkle_root: w.merkle_root, anchor: w.anchor, binder_pub: w.binder_pub };
  chk('binder_wallet_signature', await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, await importPub(w.binder_pub), unhex(w.sig), canon(ws)).catch(() => false));
  const leaves = [await leaf(w.genesis)]; for (const e of w.events) leaves.push(await leaf(e));
  chk('merkle_root_integrity', (await merkle(leaves)) === w.merkle_root);
  chk('binder_key_matches_pubkeys', w.binder_pub === binderPubHex);
  chk('model_identity_present', !!evs.model_identity);
  chk('output_bound_to_prompt', evs.output && evs.output.body.prompt_hash === w.genesis.body.prompt_hash);
  chk('anchored', !!(w.anchor && w.anchor.tx));
  return { ok: checks.every((c) => c[1]), checks };
}
