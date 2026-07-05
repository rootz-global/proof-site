// manifest-service.mjs — the Signed Manifest of Hashes (DESIGN §3.9)
// Pure builders + an in-memory session store with disposition. Signing is done by the caller
// with sign-mcp.cjs (so the manifest verifies via the existing /verify path).

import { createHash, randomBytes } from 'node:crypto';

export const sha256 = (s) => createHash('sha256').update(typeof s === 'string' ? s : JSON.stringify(s)).digest('hex');

export function merkleHex(leavesHex) {
  if (!leavesHex.length) return sha256('');
  let lvl = leavesHex.map((h) => Buffer.from(h, 'hex'));
  while (lvl.length > 1) {
    const nx = [];
    for (let i = 0; i < lvl.length; i += 2) {
      const a = lvl[i], b = i + 1 < lvl.length ? lvl[i + 1] : lvl[i];
      nx.push(createHash('sha256').update(Buffer.concat([a, b])).digest());
    }
    lvl = nx;
  }
  return lvl[0].toString('hex');
}

// Demo context the "service" assembles around the user's prompt — so the manifest has real parts.
export const DEMO_SYSTEM = 'You are a helpful assistant operating under Rootz Signed-Manifest provenance. Answer plainly.';
export const DEMO_TOOLS = [
  { name: 'search_docs', def: 'search_docs(query: string): search the documents attached to this session' },
  { name: 'now', def: 'now(): return the current UTC time' },
];

export const assemble = (prompt, context) =>
  [DEMO_SYSTEM, ...(context || []).map((c) => `[${c.ref || 'doc'}]\n${c.text || ''}`), `User: ${prompt}`].join('\n\n');

// Build the manifest object (all hashes) + its Merkle root. Sign the object outside (sign-mcp).
export function buildManifest({ session_id, prompt, context, model, output, history_root }) {
  const system_prompt_hash = sha256(DEMO_SYSTEM);
  const tools = DEMO_TOOLS.map((t) => ({ name: t.name, def_hash: sha256(t.def) }));
  const ctx = (context || []).map((c) => ({ ref: c.ref || 'doc', hash: sha256(c.text || '') }));
  const prompt_hash = sha256(prompt);
  const output_hash = sha256(output);
  const params_hash = sha256(JSON.stringify({ max_tokens: 1024 }));
  const hr = history_root || sha256('');
  const now = new Date();
  const object = {
    v: 1, kind: 'ai-interaction-manifest', session_id,
    system_prompt_hash, tools, context: ctx, history_root: hr,
    prompt_hash, model_id: model, params_hash, output_hash,
    nonce: randomBytes(12).toString('hex'),
    ts: now.toISOString(), exp: new Date(now.getTime() + 5 * 60000).toISOString(),
  };
  const leaves = [system_prompt_hash, ...tools.map((t) => t.def_hash), ...ctx.map((c) => c.hash), hr, prompt_hash, output_hash];
  return { object, manifest_root: merkleHex(leaves) };
}

// --- session store (accumulation + disposition) ---
const SESS = new Map(); // id -> { created, disposition, email, entries:[{root,prompt_hash,output_hash,ts}], running_root, ended, held_until }
const TTL_MS = 24 * 3600 * 1000;

export function sessionAppend(id, entry, disposition, email) {
  let s = SESS.get(id);
  if (!s) { s = { created: Date.now(), entries: [], running_root: null, disposition: 'hold' }; SESS.set(id, s); }
  s.entries.push(entry);
  if (disposition) s.disposition = disposition;
  if (email) s.email = email;
  s.running_root = merkleHex(s.entries.map((e) => e.root));
  return s;
}
export function sessionGet(id) {
  const s = SESS.get(id);
  if (!s) return null;
  if (s.held_until && s.held_until < Date.now()) { SESS.delete(id); return null; }
  return s;
}
export function historyRoot(id) {
  const s = SESS.get(id);
  return s && s.entries.length ? s.running_root : null;
}
// Execute the disposition when the session ends/drops. Returns a receipt (actions are demo-labeled).
export function sessionEnd(id, disposition, email) {
  const s = SESS.get(id);
  if (!s) return { ok: false, error: 'unknown-session' };
  s.disposition = disposition || s.disposition;
  if (email) s.email = email;
  s.ended = new Date().toISOString();
  const base = { ok: true, session_id: id, messages: s.entries.length, running_root: s.running_root, disposition: s.disposition };
  switch (s.disposition) {
    case 'hold':
      s.held_until = Date.now() + TTL_MS;
      return { ...base, recover: `/api/manifest/session/${id}`, expires_in_hours: 24 };
    case 'email':
      return { ...base, note: `(demo) the session manifest root would be emailed to ${s.email || '—'}` };
    case 'wallet':
      return { ...base, wallet_id: 'w_' + randomBytes(9).toString('hex'), note: '(demo) session manifest written to your data wallet as a write-only member' };
    case 'discard':
      SESS.delete(id);
      return { ...base, note: 'session manifest discarded' };
    default:
      return base;
  }
}
export function sweep() { const now = Date.now(); for (const [id, s] of SESS) if ((s.held_until && s.held_until < now) || (!s.held_until && now - s.created > TTL_MS)) SESS.delete(id); }
