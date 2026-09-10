// rim.mjs — NVIDIA Reference Integrity Manifest client.
//
// Fetches and parses NVIDIA's PUBLICLY AVAILABLE golden measurement values.
// No GPU, no credentials, no entitlement required — verified 2026-09-10.
//
// This is the reference side of attestation verification: what the measurements
// SHOULD be. The attester supplies what they ARE. Comparing the two is the job.
//
//   node rim.mjs list [filter]      list available RIM ids
//   node rim.mjs get <id>           fetch + parse one RIM to a reference set
//   node rim.mjs save <id> <file>   write the parsed reference set as JSON

const RIM_BASE = 'https://rim.attestation.nvidia.com/v1/rim';

async function getJson(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(30000) });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} for ${url}`);
  return r.json();
}

export async function listIds(filter) {
  const { ids } = await getJson(`${RIM_BASE}/ids`);
  return filter ? ids.filter(i => i.toUpperCase().includes(filter.toUpperCase())) : ids;
}

// Minimal attribute reader — the SWID is well-formed and machine-generated,
// so a targeted extractor beats pulling in an XML dependency.
function attrs(tag) {
  const out = {};
  for (const m of tag.matchAll(/([\w:.\-]+)\s*=\s*"([^"]*)"/g)) out[m[1]] = m[2];
  return out;
}

// The hash attribute is namespace-prefixed (e.g. ns2:Hash0) and the prefix is
// declared on the root as an xmlenc URI naming the digest. Resolve it properly —
// the digest algorithm is a load-bearing property, not decoration.
function resolveAlg(xml, hashKey) {
  const prefix = hashKey.includes(':') ? hashKey.split(':')[0] : null;
  if (!prefix) return 'unknown';
  const decl = xml.match(new RegExp(`xmlns:${prefix}\\s*=\\s*"([^"]*)"`));
  if (!decl) return prefix;
  const uri = decl[1];
  const m = uri.match(/#(sha\d+)/i) || uri.match(/(sha\d+)/i);
  return m ? m[1].toLowerCase() : uri;
}

export function parseRim(rimB64) {
  const xml = Buffer.from(rimB64, 'base64').toString('utf8');

  const idTag = xml.match(/<SoftwareIdentity\b[^>]*>/);
  const identity = idTag ? attrs(idTag[0]) : {};

  const entityTag = xml.match(/<[\w:]*Entity\b[^>]*\/?>/);
  const entity = entityTag ? attrs(entityTag[0]) : {};

  const metaTag = xml.match(/<[\w:]*Meta\b[^>]*\/?>/);
  const meta = metaTag ? attrs(metaTag[0]) : {};

  // Measurement resources: index -> hash. Hash attribute is namespaced by digest alg.
  const measurements = [];
  for (const m of xml.matchAll(/<[\w:]*Resource\b[^>]*\/>/g)) {
    const a = attrs(m[0]);
    if ((a.type || '').toLowerCase() !== 'measurement') continue;
    const hashKey = Object.keys(a).find(k => /Hash\d*$/i.test(k));
    measurements.push({
      index: Number(a.index),
      name: a.name,
      size: Number(a.size),
      active: a.active === 'True' || a.active === 'true',
      alternatives: Number(a.alternatives || 1),
      digestAlg: hashKey ? resolveAlg(xml, hashKey) : 'unknown',
      value: hashKey ? a[hashKey] : null,
    });
  }
  measurements.sort((a, b) => a.index - b.index);

  const signatures = [...xml.matchAll(/<[\w:]*Signature\b/g)].length;
  const signed = signatures > 0;

  return { identity, entity, meta, measurements, signed, signatureElements: signatures,
           rawBytes: xml.length };
}

export async function getReferenceSet(id) {
  const doc = await getJson(`${RIM_BASE}/${id}`);
  const parsed = parseRim(doc.rim);
  return {
    id: doc.id,
    sha256: doc.sha256,
    lastUpdated: doc.last_updated,
    format: doc.rim_format,
    fetchedAt: new Date().toISOString(),
    source: `${RIM_BASE}/${id}`,
    ...parsed,
  };
}

// --- CLI (only when run directly, not on import) ---
const isMain = process.argv[1] && process.argv[1].endsWith('rim.mjs');
const [cmd, arg1, arg2] = isMain ? process.argv.slice(2) : [];
if (isMain) {
if (cmd === 'list') {
  const ids = await listIds(arg1);
  console.log(`${ids.length} RIM id(s)${arg1 ? ` matching "${arg1}"` : ''}`);
  ids.slice(0, 40).forEach(i => console.log('  ' + i));
  if (ids.length > 40) console.log(`  … ${ids.length - 40} more`);
} else if (cmd === 'get' || cmd === 'save') {
  if (!arg1) { console.error('need a RIM id'); process.exit(1); }
  const set = await getReferenceSet(arg1);
  const active = set.measurements.filter(m => m.active);
  const nonZero = set.measurements.filter(m => m.value && !/^0+$/.test(m.value));
  if (cmd === 'save') {
    const { writeFileSync } = await import('fs');
    writeFileSync(arg2 || `${arg1}.json`, JSON.stringify(set, null, 2));
    console.log(`wrote ${arg2 || arg1 + '.json'}`);
  }
  console.log(`RIM            : ${set.id}`);
  console.log(`format         : ${set.format}   last updated: ${set.lastUpdated}`);
  console.log(`sha256         : ${set.sha256}`);
  console.log(`issuer         : ${set.entity.name || '?'}  (${set.entity.role || '?'})`);
  console.log(`product        : ${set.identity.name || '?'}  version ${set.identity.version || '?'}`);
  console.log(`tagId          : ${set.identity.tagId || '?'}`);
  console.log(`signed         : ${set.signed ? 'YES' : 'NO'}  (${set.signatureElements} signature elements)`);
  console.log(`measurements   : ${set.measurements.length} total · ${active.length} active · ${nonZero.length} non-zero`);
  console.log(`digest alg     : ${[...new Set(set.measurements.map(m => m.digestAlg))].join(', ')}`);
  if (nonZero.length) {
    console.log('\nfirst non-zero reference measurements:');
    nonZero.slice(0, 5).forEach(m =>
      console.log(`  [${String(m.index).padStart(2)}] ${m.name.padEnd(16)} ${m.value.slice(0, 48)}…`));
  }
} else {
  console.log('usage: node rim.mjs list [filter] | get <id> | save <id> [file]');
}
}
