// demo.mjs — end-to-end, no silicon.
// Fetches REAL NVIDIA golden values, runs the binding + verification path,
// then proves the verifier actually detects tampering.
import { getReferenceSet } from './rim.mjs';
import { StubAttester, bindingNonce } from './attester.mjs';
import { verifyMeasurements, summarise } from './verify.mjs';
import { createHash } from 'crypto';

const RIM_ID = process.argv[2] || 'NV_GPU_CC_DRIVER_GB100_580.178.04';
const h = s => createHash('sha256').update(s).digest('hex');

console.log(`\n── fetching real NVIDIA reference values ──`);
const ref = await getReferenceSet(RIM_ID);
console.log(`   ${ref.id}  ·  ${ref.measurements.length} measurements, ${ref.measurements.filter(m=>m.active).length} active`);
console.log(`   signed by ${ref.entity.name}  ·  format ${ref.format}`);

// The binding seam: our application evidence rides in the 32-byte nonce.
const nonce = bindingNonce({
  signedPromptHash: h('customer-signed prompt goes here'),
  modelMeasurement: h('model boot+load measurement'),
  policyId: 'rootz/measured-ai/v1',
});
console.log(`\n── binding nonce (prompt ‖ model ‖ policy) ──\n   ${nonce}`);

const attester = new StubAttester({ referenceSet: ref });

console.log(`\n── CASE 1: honest evidence ──`);
const good = await attester.collect(nonce);
console.log(summarise(verifyMeasurements(good, ref)));

console.log(`\n── CASE 2: one measurement tampered ──`);
const bad = structuredClone(good);
bad.measurements[0].value = 'de' + bad.measurements[0].value.slice(2);
console.log(summarise(verifyMeasurements(bad, ref)));

console.log(`\n── CASE 3: evidence against the WRONG driver version ──`);
const other = await getReferenceSet('NV_GPU_CC_DRIVER_GB100_580.159.03');
console.log(summarise(verifyMeasurements(good, other)));
console.log();
