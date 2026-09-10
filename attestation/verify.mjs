// verify.mjs — compare REPORTED measurements against NVIDIA's GOLDEN values.
//
// This is the relying-party job, and it is fully exercisable today against the
// public RIM service. The verdict is a stated DEPTH, never a boolean: what was
// checked, what matched, and what we could not check.

export function verifyMeasurements(evidence, referenceSet) {
  const ref = new Map(referenceSet.measurements.map(m => [m.index, m]));
  const checked = [], mismatched = [], unknown = [], notInEvidence = [];

  for (const m of evidence.measurements) {
    const r = ref.get(m.index);
    if (!r) { unknown.push({ index: m.index, reason: 'no reference value for this index' }); continue; }
    const match = (m.value || '').toLowerCase() === (r.value || '').toLowerCase();
    (match ? checked : mismatched).push({
      index: m.index, name: r.name, alg: r.digestAlg,
      reported: m.value, expected: r.value, match,
    });
  }
  for (const r of referenceSet.measurements) {
    if (r.active && !evidence.measurements.some(m => m.index === r.index))
      notInEvidence.push({ index: r.index, name: r.name });
  }

  const activeRefs = referenceSet.measurements.filter(m => m.active).length;
  const pass = mismatched.length === 0 && checked.length > 0;

  return {
    pass,
    // Coverage is the honest number: a pass over 3 of 25 measurements is not the
    // same claim as a pass over 25 of 25, and the record must say which.
    coverage: { verified: checked.length, activeReferences: activeRefs,
                ratio: activeRefs ? +(checked.length / activeRefs).toFixed(3) : 0 },
    checked, mismatched, unknown, notInEvidence,
    referenceId: referenceSet.id,
    referenceSha256: referenceSet.sha256,
    referenceSigned: referenceSet.signed,
    evidenceSource: evidence.source,
    nonce: evidence.nonce,
    // The depth this evidence can honestly support.
    depth: depthOf(evidence, referenceSet, pass, checked.length, activeRefs),
    verifiedAt: new Date().toISOString(),
  };
}

function depthOf(evidence, ref, pass, verified, activeRefs) {
  if (!pass) return { level: 'FAIL', why: 'one or more reported measurements did not match the reference' };
  if (evidence.source === 'stub')
    return { level: 'L0', why: 'synthetic evidence — no device key signed this. Development only.' };
  if (!ref.signed)
    return { level: 'L1', why: 'reference manifest was not signature-verified' };
  if (verified < activeRefs)
    return { level: 'L2-partial', why: `matched ${verified} of ${activeRefs} active references — partial coverage` };
  return { level: 'L2', why: 'all active reference measurements matched a signed manifest' };
}

export function summarise(result) {
  const L = [];
  L.push(`verdict        : ${result.pass ? 'PASS' : 'FAIL'}`);
  L.push(`depth          : ${result.depth.level} — ${result.depth.why}`);
  L.push(`coverage       : ${result.coverage.verified}/${result.coverage.activeReferences} active references (${(result.coverage.ratio * 100).toFixed(1)}%)`);
  L.push(`reference      : ${result.referenceId}`);
  L.push(`ref signed     : ${result.referenceSigned ? 'YES' : 'NO'}   ref sha256: ${result.referenceSha256.slice(0, 24)}…`);
  L.push(`evidence source: ${result.evidenceSource}`);
  L.push(`bound nonce    : ${result.nonce.slice(0, 32)}…`);
  if (result.mismatched.length) {
    L.push(`\nMISMATCHES (${result.mismatched.length}):`);
    result.mismatched.slice(0, 5).forEach(m =>
      L.push(`  [${m.index}] ${m.name}\n      reported ${m.reported.slice(0, 40)}…\n      expected ${m.expected.slice(0, 40)}…`));
  }
  if (result.notInEvidence.length) L.push(`\nactive references absent from evidence: ${result.notInEvidence.length}`);
  return L.join('\n');
}
