/**
 * fleet-core/sign-mcp.js — SIGNED MCP: crypto-agile, PQ-ready, identity-anchored signatures
 * for Model Context Protocol responses + tool/resource definitions.
 *
 * See claud project/signed-mcp/DESIGN-signed-mcp.md. Implements the Five Eyes (2026-04-30) +
 * NSA CSI MCP-Security (May 2026) controls: sign with nonce + timestamp in a bounded window;
 * bind to time + context; sign tool definitions (anti-poisoning); multi-sig hybrid (classical + PQ).
 *
 * SPLIT: services SIGN (vendor this in, politics first); proof.rootz.global VERIFIES + EXPLAINS.
 * Both halves are here so the one module is the source of truth; vendor a copy per repo (don't cross-require).
 *
 * Zero deps for classical algs (Ed25519 + ECDSA P-256 via Node `crypto`). PQ (ml-dsa-65) activates
 * iff `@noble/post-quantum` is installed — otherwise the registry marks it unavailable (no crash,
 * no silent downgrade: signing omits an unavailable alg and records it).
 */
'use strict';
const crypto = require('crypto');

// ----------------------------------------------------------------------------
// RFC 8785 JSON Canonicalization Scheme (JCS) — the one byte-exact-critical part.
// Recursive key sort (UTF-16 code unit) + JSON.stringify for primitives (ECMAScript number form).
// Conformant for the JSON value space MCP envelopes use; pinned by test-vectors.json. For adversarial
// number edge cases, swap in the `canonicalize` npm package (drop-in).
// ----------------------------------------------------------------------------
function jcsString(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'number') {
    if (!isFinite(v)) throw new Error('JCS: non-finite number');
    return JSON.stringify(v); // ECMAScript Number->String, == RFC 8785 §3.2.2.3 for finite numbers
  }
  if (t === 'boolean' || t === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcsString).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(v).sort(); // default sort = UTF-16 code unit order
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcsString(v[k])).join(',') + '}';
  }
  throw new Error('JCS: unsupported value type ' + t);
}
function jcs(v) { return Buffer.from(jcsString(v), 'utf8'); }
function sha256(buf) { return crypto.createHash('sha256').update(buf).digest(); }
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s) => Buffer.from(s, 'base64url');

// ----------------------------------------------------------------------------
// Algorithm registry — verifiers dispatch by `alg`. NO hardcoded alg anywhere else.
// Each entry: { class, available, sign(msgBuf, privPem|sk)->Buffer, verify(msgBuf, sig, pubPem|pk)->bool,
//               keygen()->{pub,priv}, jwk(pubPem)->jwk }
// ----------------------------------------------------------------------------
const REG = {};

REG['ed25519'] = {
  class: 'classical', available: true,
  keygen() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return { pub: publicKey.export({ type: 'spki', format: 'pem' }),
             priv: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
  },
  sign(msg, privPem) { return crypto.sign(null, msg, privPem); },
  verify(msg, sig, pubPem) { try { return crypto.verify(null, msg, pubPem, sig); } catch { return false; } },
  jwk(pubPem) {
    const raw = crypto.createPublicKey(pubPem).export({ format: 'jwk' });
    return { kty: raw.kty, crv: raw.crv, x: raw.x };
  },
};

REG['ecdsa-p256'] = {
  class: 'classical', available: true,
  keygen() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return { pub: publicKey.export({ type: 'spki', format: 'pem' }),
             priv: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
  },
  // DER-encoded ECDSA over SHA-256 (matches ATTP/MCPS + NSA convention).
  sign(msg, privPem) { return crypto.sign('sha256', msg, privPem); },
  verify(msg, sig, pubPem) { try { return crypto.verify('sha256', msg, pubPem, sig); } catch { return false; } },
  jwk(pubPem) {
    const raw = crypto.createPublicKey(pubPem).export({ format: 'jwk' });
    return { kty: raw.kty, crv: raw.crv, x: raw.x, y: raw.y };
  },
};

// ML-DSA-65 (FIPS 204) — primary PQ. Provider-injected, because the canonical Rootz PQ library
// (@rootz/pq-crypto, "the single source of truth") is ESM while this capability is CJS: the *import*
// is async, but pqSign/pqVerify are sync once loaded. Call `await initPqProvider()` once at startup to
// activate PQ; classical algs need zero init. NO silent downgrade — until a provider loads, ml-dsa-65
// is `available: false` and sign() simply omits it (and records that it did).
let _pq = null; // { sign(sk,msg)->Uint8Array, verify(pk,msg,sig)->bool, keygen()->{publicKey,secretKey} }

/**
 * Activate the PQ provider. Preference order:
 *   1. opts.provider — inject {sign, verify, keygen} directly (tests / custom)
 *   2. @rootz/pq-crypto  (the canonical Rootz lib: ML-DSA-65 FIPS 204, CNSA 2.0) — opts.distPath or
 *      ROOTZ_PQ_CRYPTO_DIST or known monorepo dist locations
 *   3. @noble/post-quantum (audited pure-JS fallback)
 * Returns true if PQ is now available.
 */
async function initPqProvider(opts = {}) {
  if (_pq) return true;
  if (opts.provider && opts.provider.sign && opts.provider.verify && opts.provider.keygen) {
    _pq = opts.provider; REG['ml-dsa-65'].available = true; return true;
  }
  // 2: canonical Rootz PQ library (ESM) via dynamic import
  const { pathToFileURL } = require('url');
  const fs = require('fs');
  const candidates = [
    opts.distPath, process.env.ROOTZ_PQ_CRYPTO_DIST,
    'c:/Users/StevenSprague/OneDrive - Rivetz Corp/Rootz/claud project/rootz-monorepo/packages/pq-crypto/dist/index.js',
    'c:/Users/StevenSprague/OneDrive - Rivetz Corp/Rootz/claud project/rootz-v6/packages/pq-crypto/dist/index.js',
    '/home/ubuntu/fleet/fleet-core/pq-crypto/dist/index.js',
  ].filter(Boolean);
  for (const cand of candidates) {
    try {
      if (!fs.existsSync(cand)) continue;
      const m = await import(pathToFileURL(cand).href);
      if (typeof m.pqSign === 'function' && typeof m.pqVerify === 'function' && typeof m.signKeygen === 'function') {
        _pq = { sign: m.pqSign, verify: m.pqVerify, keygen: m.signKeygen };
        REG['ml-dsa-65'].available = true; return true;
      }
    } catch { /* try next */ }
  }
  // 3: @noble/post-quantum fallback
  try {
    const noble = await import('@noble/post-quantum/ml-dsa');
    const d = noble.ml_dsa65;
    _pq = { sign: (sk, msg) => d.sign(sk, msg), verify: (pk, msg, sig) => d.verify(pk, msg, sig), keygen: () => d.keygen() };
    REG['ml-dsa-65'].available = true; return true;
  } catch { /* absent */ }
  return false;
}

REG['ml-dsa-65'] = {
  class: 'pq', available: false, // flipped true by initPqProvider()
  keygen() {
    if (!_pq) throw new Error('ml-dsa-65 unavailable: await initPqProvider() first (loads @rootz/pq-crypto)');
    const k = _pq.keygen();
    return { pub: b64u(k.publicKey), priv: b64u(k.secretKey) }; // raw keys, base64url
  },
  sign(msg, privB64u) {
    if (!_pq) throw new Error('ml-dsa-65 unavailable: await initPqProvider() first');
    return Buffer.from(_pq.sign(fromB64u(privB64u), new Uint8Array(msg)));
  },
  verify(msg, sig, pubB64u) {
    if (!_pq) return false;
    try { return _pq.verify(fromB64u(pubB64u), new Uint8Array(msg), new Uint8Array(sig)); } catch { return false; }
  },
  jwk(pubB64u) { return { kty: 'AKP', alg: 'ML-DSA-65', pub: pubB64u }; }, // draft-ietf JOSE PQ form
};

function algsAvailable() { return Object.keys(REG).filter((a) => REG[a].available); }
function pqAvailable() { return !!_pq; }

// ----------------------------------------------------------------------------
// Keyset — load/generate a multi-alg signing keyset (mirrors archive.js key handling).
// Shape: { iss, kid, corpid?, keys: { <alg>: {pub, priv} } }
// ----------------------------------------------------------------------------
function generateKeyset({ iss, kid, corpid = null, algs = ['ed25519', 'ecdsa-p256'] } = {}) {
  if (!iss || !kid) throw new Error('generateKeyset: iss + kid required');
  const keys = {};
  for (const a of algs) {
    if (!REG[a]) throw new Error('unknown alg ' + a);
    if (!REG[a].available) continue; // skip unavailable (e.g. PQ lib absent) — recorded by caller
    keys[a] = REG[a].keygen();
  }
  return { iss, kid, corpid, keys };
}

// Public-only view (safe to publish): JWKS + DNS selector records.
function publicKeyset(keyset) {
  const out = { iss: keyset.iss, kid: keyset.kid, corpid: keyset.corpid || null, keys: {} };
  for (const a of Object.keys(keyset.keys)) out.keys[a] = { pub: keyset.keys[a].pub };
  return out;
}
function jwks(keyset) {
  const ks = [];
  for (const a of Object.keys(keyset.keys)) {
    ks.push(Object.assign({ kid: keyset.kid, alg: a, use: 'sig' }, REG[a].jwk(keyset.keys[a].pub)));
  }
  return { keys: ks };
}
// DKIM-style selector TXT record values, one per alg. Name: `<kid>._mcpkey.<iss>`.
function dnsSelectorRecords(keyset) {
  const recs = {};
  for (const a of Object.keys(keyset.keys)) {
    const pub = keyset.keys[a].pub;
    const p = (typeof pub === 'string' && pub.includes('BEGIN'))
      ? pub.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '') // strip PEM armor → base64
      : pub;
    recs[`${keyset.kid}._mcpkey.${keyset.iss}`] = `v=RMCP1; a=${a}; k=${p}`;
  }
  return recs;
}

// A keyResolver maps (iss, kid, alg) -> public key (PEM or b64u). For local/single-keyset use:
function resolverFromKeyset(keyset) {
  return (iss, kid, alg) => {
    if (iss !== keyset.iss || kid !== keyset.kid) return null;
    return keyset.keys[alg] ? keyset.keys[alg].pub : null;
  };
}

// ----------------------------------------------------------------------------
// ENVELOPE — sign. Two-step: payload_hash (SHA-256 of JCS(content)) inside a protected header
// that every signature covers. `algs` is in the header → downgrade/stripping is detectable.
// ----------------------------------------------------------------------------
const ENVELOPE_KEY = 'rootz.global/sig';
const DEFAULT_TTL_SEC = 300; // bounded validity window (NSA "expiration timestamp")

function isoSecondsFromNow(sec, nowMs) { return new Date((nowMs ?? Date.now()) + sec * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'); }

/**
 * sign(signedObject, { keyset, ctx, algs?, ttlSec?, nowMs? }) -> envelope
 *   signedObject: the result (minus _meta) OR a single tool/resource definition object.
 *   ctx: { method, tool?, req_id?, req_hash?, session?, aud? } — context binding.
 */
function sign(signedObject, { keyset, ctx = {}, algs, ttlSec = DEFAULT_TTL_SEC, nowMs } = {}) {
  if (!keyset || !keyset.keys) throw new Error('sign: keyset required');
  const use = (algs || Object.keys(keyset.keys)).filter((a) => keyset.keys[a] && REG[a] && REG[a].available);
  if (!use.length) throw new Error('sign: no available algs in keyset');
  const now = nowMs ?? Date.now();
  const header = {
    v: 1,
    iss: keyset.iss,
    kid: keyset.kid,
    canon: 'RFC8785',
    payload: { alg: 'sha-256', hash: b64u(sha256(jcs(signedObject))) },
    ts: isoSecondsFromNow(0, now),
    exp: isoSecondsFromNow(ttlSec, now),
    nonce: b64u(crypto.randomBytes(16)),
    ctx,
    algs: use.slice().sort(),
  };
  if (keyset.corpid) header.corpid = keyset.corpid;
  const signingInput = jcs(header);
  const sigs = {};
  for (const a of header.algs) sigs[a] = b64u(REG[a].sign(signingInput, keyset.keys[a].priv));
  return Object.assign({}, header, { sigs });
}

/** Attach a signature to a result's _meta in place, returning the result. */
function signResult(result, opts) {
  const clean = Object.assign({}, result);
  delete clean._meta;
  const env = sign(clean, opts);
  result._meta = Object.assign({}, result._meta, { [ENVELOPE_KEY]: env });
  return result;
}

/** Sign each tool/resource definition in a list (anti-tool-poisoning). Adds def._meta[ENVELOPE_KEY]. */
function signDefinitions(defs, baseOpts) {
  return defs.map((def) => {
    const clean = Object.assign({}, def); delete clean._meta;
    const ctx = Object.assign({ method: 'tools/list', tool: def.name }, baseOpts.ctx || {});
    const env = sign(clean, Object.assign({}, baseOpts, { ctx }));
    return Object.assign({}, def, { _meta: Object.assign({}, def._meta, { [ENVELOPE_KEY]: env }) });
  });
}

// ----------------------------------------------------------------------------
// ENVELOPE — verify. Fail-closed. Checks: integrity, freshness, replay, downgrade, context, signatures.
// ----------------------------------------------------------------------------
/**
 * verify(signedObject, envelope, opts) -> { valid, reasons[], algs: {<alg>: bool} }
 *   opts.keyResolver(iss,kid,alg) -> pubKey | null   (required to check signatures)
 *   opts.nowMs, opts.skewSec (default 60)
 *   opts.replayStore: { has(nonce):bool, add(nonce, expMs):void }  (optional; enables replay check)
 *   opts.expectCtx: subset of ctx fields that MUST match (e.g. {aud, req_id, req_hash})
 *   opts.policy: 'all' (default; every claimed alg must verify) | 'any-classical-plus-pq'
 */
function verify(signedObject, envelope, opts = {}) {
  const reasons = [];
  const perAlg = {};
  const now = opts.nowMs ?? Date.now();
  const skew = (opts.skewSec ?? 60) * 1000;
  if (!envelope || typeof envelope !== 'object') return { valid: false, reasons: ['no-envelope'], algs: {} };
  if (envelope.canon !== 'RFC8785') reasons.push('bad-canon');

  // 1. integrity
  try {
    const want = b64u(sha256(jcs(signedObject)));
    if (!envelope.payload || envelope.payload.hash !== want) reasons.push('payload-hash-mismatch');
  } catch (e) { reasons.push('payload-hash-error'); }

  // 2. freshness (bounded window)
  const ts = Date.parse(envelope.ts), exp = Date.parse(envelope.exp);
  if (!(ts >= 0) || !(exp >= 0)) reasons.push('bad-timestamps');
  else {
    if (now > exp + skew) reasons.push('expired');
    if (now < ts - skew) reasons.push('not-yet-valid');
  }

  // 3. context binding
  if (opts.expectCtx) {
    const c = envelope.ctx || {};
    for (const k of Object.keys(opts.expectCtx)) {
      if (c[k] !== opts.expectCtx[k]) reasons.push('ctx-mismatch:' + k);
    }
  }

  // 4. signatures + downgrade guard. Reconstruct protected header = envelope minus sigs.
  const header = Object.assign({}, envelope); delete header.sigs;
  const signingInput = jcs(header);
  const claimed = Array.isArray(envelope.algs) ? envelope.algs : [];
  if (!claimed.length) reasons.push('no-algs');
  const sigs = envelope.sigs || {};
  for (const a of claimed) {
    if (!(a in sigs)) { perAlg[a] = false; reasons.push('missing-sig:' + a); continue; } // downgrade/strip
    if (!REG[a]) { perAlg[a] = false; reasons.push('unknown-alg:' + a); continue; }
    const pub = opts.keyResolver ? opts.keyResolver(envelope.iss, envelope.kid, a) : null;
    if (!pub) { perAlg[a] = false; reasons.push('no-key:' + a); continue; }
    const ok = REG[a].verify(signingInput, fromB64u(sigs[a]), pub);
    perAlg[a] = ok;
    if (!ok) reasons.push('bad-sig:' + a);
  }
  // also flag any signature present but not claimed in the header (not covered → suspicious)
  for (const a of Object.keys(sigs)) if (!claimed.includes(a)) reasons.push('uncovered-sig:' + a);

  // 5. replay (only after the rest is sound, to avoid burning a nonce on a junk message)
  let replayBad = false;
  if (opts.replayStore && envelope.nonce) {
    if (opts.replayStore.has(envelope.nonce)) { replayBad = true; reasons.push('replay'); }
  }

  // policy
  const classicalPass = claimed.filter((a) => REG[a] && REG[a].class === 'classical' && perAlg[a]).length;
  const pqClaimed = claimed.filter((a) => REG[a] && REG[a].class === 'pq');
  const pqPass = pqClaimed.filter((a) => perAlg[a]).length;
  let sigPolicyOk;
  if (opts.policy === 'any-classical-plus-pq') {
    sigPolicyOk = classicalPass >= 1 && (pqClaimed.length === 0 || pqPass === pqClaimed.length);
  } else { // 'all' (default, fail-closed)
    sigPolicyOk = claimed.length > 0 && claimed.every((a) => perAlg[a]);
  }
  if (!sigPolicyOk) reasons.push('sig-policy-failed');

  const valid = reasons.length === 0 && !replayBad && sigPolicyOk;
  // record nonce only on an otherwise-valid message
  if (valid && opts.replayStore && envelope.nonce) opts.replayStore.add(envelope.nonce, exp);
  return { valid, reasons, algs: perAlg };
}

/** Convenience: verify a result that carries _meta[ENVELOPE_KEY]. */
function verifyResult(result, opts) {
  const env = result && result._meta && result._meta[ENVELOPE_KEY];
  const clean = Object.assign({}, result); delete clean._meta;
  return verify(clean, env, opts);
}

// In-memory replay store (swap for Redis/SQLite in prod). Evicts expired nonces lazily.
function memoryReplayStore() {
  const m = new Map();
  return {
    has(n) { const e = m.get(n); if (e && e < Date.now()) { m.delete(n); return false; } return m.has(n); },
    add(n, expMs) { m.set(n, expMs || Date.now() + DEFAULT_TTL_SEC * 1000); },
    size() { return m.size; },
  };
}

// ----------------------------------------------------------------------------
// LAYER 3 — MCP Session Audit Log (data-wallet) + Merkle batch anchor.
// Per (server, client) append-only, hash-linked log of every exchange. Window -> Merkle root ->
// one on-chain Note (cheap provable timestamps). Shareable to BOTH parties for dispute-grade audit.
// On-chain + encryption are HOOKS (anchorFn / encryptFn) so the prototype pulls no chain deps.
// ----------------------------------------------------------------------------
// `leafBufs` are already leaf HASHES (entry.leaf = sha256(jcs(entry))). Do NOT re-hash here, so
// windowRoot() and inclusionProof() agree. Production Layer-3 should swap in @rootz/pq-crypto's
// computeMerkleRoot/createBlock (the single source of truth) for domain-separated, PQ-signed blocks.
function merkleRoot(leafBufs) {
  if (!leafBufs.length) return Buffer.alloc(32);
  let level = leafBufs.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i], r = level[i + 1] || level[i]; // duplicate last if odd
      next.push(sha256(Buffer.concat([l, r])));
    }
    level = next;
  }
  return level[0];
}

class SessionAuditLog {
  constructor({ server, client }) {
    this.server = server; this.client = client;
    this.entries = []; // { seq, req_hash, resp_envelope, prev_link, leaf }
  }
  _prevLink() {
    if (!this.entries.length) return b64u(Buffer.alloc(32));
    const last = this.entries[this.entries.length - 1];
    return b64u(sha256(jcs({ seq: last.seq, req_hash: last.req_hash, resp_envelope: last.resp_envelope, prev_link: last.prev_link })));
  }
  append({ requestParams, responseEnvelope }) {
    const seq = this.entries.length;
    const req_hash = b64u(sha256(jcs(requestParams ?? null)));
    const prev_link = this._prevLink();
    const entry = { seq, req_hash, resp_envelope: responseEnvelope, prev_link };
    entry.leaf = sha256(jcs({ seq, req_hash, resp_envelope: responseEnvelope, prev_link }));
    this.entries.push(entry);
    return entry;
  }
  /** Merkle root over a window of entries [from, to). One on-chain Note covers the window. */
  windowRoot(from = 0, to = this.entries.length) {
    return b64u(merkleRoot(this.entries.slice(from, to).map((e) => e.leaf)));
  }
  /** Merkle inclusion proof for one entry within a window — proves "this exchange is in the anchored root". */
  inclusionProof(seq, from = 0, to = this.entries.length) {
    const leaves = this.entries.slice(from, to).map((e) => e.leaf);
    let idx = seq - from; const path = [];
    let level = leaves.slice();
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        const l = level[i], r = level[i + 1] || level[i];
        if (i === idx || i + 1 === idx) path.push({ sib: b64u(i === idx ? r : l), right: i === idx });
        next.push(sha256(Buffer.concat([l, r])));
      }
      idx = Math.floor(idx / 2); level = next;
    }
    return path;
  }
  /**
   * Anchor a window on-chain: anchorFn(rootB64u, meta) should write one Note and return a tx ref.
   * encryptFn(bytes) optionally encrypts the exportable log for secure bilateral sharing (?k= link).
   */
  async anchorWindow({ from = 0, to = this.entries.length, anchorFn, meta = {} } = {}) {
    const root = this.windowRoot(from, to);
    const m = Object.assign({ server: this.server, client: this.client, from, to, count: to - from }, meta);
    const tx = anchorFn ? await anchorFn(root, m) : null;
    return { root, meta: m, tx };
  }
  export() { return { server: this.server, client: this.client, entries: this.entries }; }
}

module.exports = {
  // canonicalization + hashing
  jcs, jcsString, sha256, b64u, fromB64u,
  // registry + keys
  REG, algsAvailable, pqAvailable, initPqProvider, generateKeyset, publicKeyset, jwks, dnsSelectorRecords, resolverFromKeyset,
  // envelope
  ENVELOPE_KEY, DEFAULT_TTL_SEC, sign, signResult, signDefinitions, verify, verifyResult,
  memoryReplayStore,
  // layer 3 audit log
  merkleRoot, SessionAuditLog,
};
