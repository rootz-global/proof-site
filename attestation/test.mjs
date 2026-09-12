// test.mjs — adversarial tests for the verifier.
//
// PREMISE: demo.mjs is weak evidence. StubAttester derives evidence FROM the
// reference set, so CASE 1 is tautological — a verifier that ignored its inputs
// and always returned PASS would pass it. These tests are written to FAIL against
// such a verifier. Each asserts a property that a cheating implementation breaks.

import { getReferenceSet } from './rim.mjs';
import { verifyMeasurements } from './verify.mjs';

const results = [];
const t = (name, fn) => { try { fn(); results.push(['PASS', name]); }
  catch (e) { results.push(['FAIL', name + ' → ' + e.message]); } };
const assert = (c, m) => { if (!c) throw new Error(m || 'assertion failed'); };

const ref = await getReferenceSet('NV_GPU_CC_DRIVER_GB100_580.178.04');
const active = ref.measurements.filter(m => m.active);
const ev = (ms, over = {}) => ({ nonce: 'a'.repeat(64), source: 'stub',
  measurements: ms, collectedAt: new Date().toISOString(), ...over });

// --- Would catch "always returns PASS" ---
t('all-wrong evidence FAILS', () => {
  const r = verifyMeasurements(ev(active.map(m => ({ index: m.index, value: 'f'.repeat(96) }))), ref);
  assert(r.pass === false, 'accepted entirely wrong measurements');
  assert(r.mismatched.length === active.length, 'did not flag every mismatch');
});

t('EVERY single-measurement corruption is caught (not just the first)', () => {
  let missed = [];
  for (const target of active) {
    const ms = active.map(m => ({ index: m.index,
      value: m.index === target.index ? flip(m.value) : m.value }));
    const r = verifyMeasurements(ev(ms), ref);
    if (r.pass) missed.push(target.index);
  }
  assert(missed.length === 0, `corruption undetected at indices: ${missed.join(',')}`);
});

// --- Would catch "returns PASS when there is nothing to check" ---
t('empty evidence does NOT pass', () => {
  const r = verifyMeasurements(ev([]), ref);
  assert(r.pass === false, 'empty evidence passed — vacuous truth bug');
});

t('evidence with only unknown indices does NOT pass', () => {
  const r = verifyMeasurements(ev([{ index: 9999, value: 'a'.repeat(96) }]), ref);
  assert(r.pass === false, 'passed with zero verified measurements');
  assert(r.unknown.length === 1, 'did not record the unknown index');
});

// --- Would catch "coverage is decorative" ---
t('coverage reflects what was ACTUALLY checked, not what was supplied', () => {
  const one = [{ index: active[0].index, value: active[0].value }];
  const r = verifyMeasurements(ev(one), ref);
  assert(r.coverage.verified === 1, `verified=${r.coverage.verified}, expected 1`);
  assert(r.coverage.activeReferences === active.length, 'activeReferences wrong');
  assert(r.coverage.ratio < 1, 'ratio claimed full coverage on one measurement');
});

// Depth gating is ORDERED: stub caps at L0 before coverage is even considered, so
// partial coverage only surfaces as L2-partial for a real evidence source. (This
// assertion was wrong on first write — it asserted L2-partial on stub evidence.
// The code was right; the test was not.)
// KILLS 'coverage-counts-supplied'. The earlier coverage test supplied exactly one
// measurement that WAS checked, so supplied==checked and the mutation was invisible.
// Found by mutate.mjs, not by inspection.
t('coverage counts CHECKED, not SUPPLIED (supplied > checked)', () => {
  const ms = [
    { index: active[0].index, value: active[0].value },   // checkable
    { index: active[1].index, value: active[1].value },   // checkable
    { index: 90001, value: 'a'.repeat(96) },              // unknown — NOT checkable
    { index: 90002, value: 'b'.repeat(96) },              // unknown — NOT checkable
  ];
  const r = verifyMeasurements(ev(ms), ref);
  assert(r.coverage.verified === 2,
    `verified=${r.coverage.verified}, expected 2 (supplied 4, checkable 2)`);
  assert(r.unknown.length === 2, `unknown=${r.unknown.length}, expected 2`);
});

t('partial coverage reports L2-partial for a REAL source', () => {
  const one = [{ index: active[0].index, value: active[0].value }];
  const r = verifyMeasurements(ev(one, { source: 'nras' }), ref);
  assert(r.depth.level === 'L2-partial', `depth=${r.depth.level}, expected L2-partial`);
  assert(r.coverage.ratio < 1, 'partial coverage not reflected');
});

t('stub caps at L0 even with partial coverage (ordering check)', () => {
  const one = [{ index: active[0].index, value: active[0].value }];
  const r = verifyMeasurements(ev(one), ref);
  assert(r.depth.level === 'L0', `stub reported ${r.depth.level}`);
});

// --- Would catch "depth is cosmetic" ---
t('stub evidence can NEVER exceed L0 even when fully correct', () => {
  const r = verifyMeasurements(ev(active.map(m => ({ index: m.index, value: m.value }))), ref);
  assert(r.pass === true, 'honest evidence should pass');
  assert(r.depth.level === 'L0', `stub reached ${r.depth.level} — depth is not gated on source`);
});

t('non-stub source with full match reaches L2', () => {
  const r = verifyMeasurements(
    ev(active.map(m => ({ index: m.index, value: m.value })), { source: 'nras' }), ref);
  assert(r.depth.level === 'L2', `expected L2, got ${r.depth.level}`);
});

// --- Would catch sloppy comparison ---
t('hex case difference still matches (case-insensitive compare)', () => {
  const r = verifyMeasurements(
    ev(active.map(m => ({ index: m.index, value: m.value.toUpperCase() }))), ref);
  assert(r.pass === true, 'case difference rejected — comparison is not normalised');
});

t('truncated hash does NOT match', () => {
  const ms = active.map(m => ({ index: m.index, value: m.value }));
  ms[0].value = ms[0].value.slice(0, -2);
  const r = verifyMeasurements(ev(ms), ref);
  assert(r.pass === false, 'truncated hash accepted — prefix comparison bug');
});

// --- Cross-reference: a DIFFERENT driver must not validate ---
const other = await getReferenceSet('NV_GPU_CC_DRIVER_GB100_580.159.03');
t('evidence for driver A fails against reference B', () => {
  const r = verifyMeasurements(ev(active.map(m => ({ index: m.index, value: m.value }))), other);
  assert(r.pass === false, 'cross-version evidence validated — versions are not distinguished');
});

t('the two reference sets genuinely differ (control)', () => {
  const a = new Map(ref.measurements.map(m => [m.index, m.value]));
  const diff = other.measurements.filter(m => a.get(m.index) !== m.value);
  assert(diff.length > 0, 'the two RIMs are identical — cross-version test proves nothing');
});

function flip(hex) {
  const c = hex[0] === 'a' ? 'b' : 'a';
  return c + hex.slice(1);
}

const fails = results.filter(r => r[0] === 'FAIL');
console.log(`\n${results.length} tests · ${results.length - fails.length} passed · ${fails.length} failed\n`);
results.forEach(([s, n]) => console.log(`  ${s === 'PASS' ? '✓' : '✗'} ${n}`));
process.exit(fails.length ? 1 : 0);
