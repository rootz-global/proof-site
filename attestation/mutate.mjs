// mutate.mjs — did the tests actually test anything?
//
// Deliberately inject plausible bugs into verify.mjs, run the suite against each,
// and report which mutations SURVIVE. A surviving mutation is a hole in the tests:
// the code could be broken that way and nothing would notice.
//
// This is the check on ME. I wrote the code and the tests; mutation testing is how
// you find out whether the tests are load-bearing or decorative.

import { readFileSync, writeFileSync, copyFileSync, unlinkSync } from 'fs';
import { execSync } from 'child_process';

const FILE = './verify.mjs', BACKUP = './verify.mjs.orig';

const MUTATIONS = [
  ['always-pass',            /const pass = [^;]+;/,            'const pass = true;'],
  ['comparison-always-true', /const match = \([^;]+;/,          'const match = true;'],
  ['drop-nonempty-guard',    /mismatched\.length === 0 && checked\.length > 0/, 'mismatched.length === 0'],
  ['case-sensitive',         /\(m\.value \|\| ''\)\.toLowerCase\(\) === \(r\.value \|\| ''\)\.toLowerCase\(\)/,
                             "(m.value || '') === (r.value || '')"],
  ['prefix-match',           /\(m\.value \|\| ''\)\.toLowerCase\(\) === \(r\.value \|\| ''\)\.toLowerCase\(\)/,
                             "(r.value||'').toLowerCase().startsWith((m.value||'').toLowerCase().slice(0,8))"],
  ['depth-ignores-source',   /if \(evidence\.source === 'stub'\)\n\s*return \{ level: 'L0'[^}]+\};/,
                             '/* stub gate removed */'],
  ['coverage-counts-supplied', /verified: checked\.length/, 'verified: evidence.measurements.length'],
  ['mismatch-never-recorded', /\(match \? checked : mismatched\)\.push/, 'checked.push'],
  ['unknown-index-counts-as-checked',
    /if \(!r\) \{ unknown\.push\(\{ index: m\.index, reason: '[^']*' \}\); continue; \}/,
    'if (!r) { checked.push({ index: m.index, match: true }); continue; }'],
];

copyFileSync(FILE, BACKUP);
const original = readFileSync(FILE, 'utf8');
const survived = [], killed = [], notApplied = [];

for (const [name, pattern, replacement] of MUTATIONS) {
  const mutated = original.replace(pattern, replacement);
  if (mutated === original) { notApplied.push(name); continue; }
  writeFileSync(FILE, mutated);
  let caught = false;
  try { execSync('node test.mjs', { stdio: 'pipe' }); }
  catch { caught = true; }                      // non-zero exit = tests failed = mutation killed
  (caught ? killed : survived).push(name);
}

copyFileSync(BACKUP, FILE);
unlinkSync(BACKUP);

console.log(`\nMUTATION TESTING — ${MUTATIONS.length} mutations\n`);
killed.forEach(n => console.log(`  ✓ KILLED    ${n}`));
survived.forEach(n => console.log(`  ✗ SURVIVED  ${n}   ← TEST SUITE HOLE`));
notApplied.forEach(n => console.log(`  ⚠ NOT APPLIED  ${n}   (pattern did not match — mutation is vacuous)`));
console.log(`\n${killed.length}/${killed.length + survived.length} applied mutations killed.`);
if (survived.length) console.log(`${survived.length} SURVIVED — the tests do not constrain that behaviour.`);
if (notApplied.length) console.log(`${notApplied.length} could not be applied — those prove nothing either way.`);
process.exit(0);
