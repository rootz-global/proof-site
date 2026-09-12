# attestation/ — the relying-party side of NVIDIA GPU attestation

**Built 2026-09-10. Runs today with NO GPU and no NVIDIA credentials.**

## Why this lives in proof-site

`proof.rootz.global` is where our claims are demonstrable rather than asserted — `/origin`,
`/signed-mcp`, `/manifest` are all live and checkable by a stranger. `origin-binder.mjs` already lives
here. The attestation evidence adapter belongs beside it, so that when NVIDIA provides hardware or a
sample token this becomes **another page a stranger can verify**, not a slide.

## What works right now, without silicon

NVIDIA's **Reference Integrity Manifest service is publicly readable** — no auth, no entitlement,
verified 2026-09-10. That is the *golden values* half of attestation, and it means the entire
relying-party path is buildable today:

```
node rim.mjs list GB100                      # 21 Blackwell manifests
node rim.mjs get NV_GPU_CC_DRIVER_GB100_580.178.04
node demo.mjs                                # full path, three cases
```

`demo.mjs` fetches a **real, NVIDIA-signed** Blackwell manifest (64 measurements, 25 active, SHA-384,
TCG format), computes the binding nonce, and runs three cases:

| Case | Result |
|---|---|
| Honest evidence | PASS · 25/25 coverage · **depth L0** (honestly — synthetic evidence, no device key) |
| One measurement tampered | **FAIL** — names the index and shows reported vs expected |
| Evidence checked against the wrong driver version | **FAIL** — catches version drift |

## The files

- **`rim.mjs`** — fetches and parses NVIDIA RIMs (base64 SWID / ISO 19770-2) into a reference
  measurement set. Resolves the namespaced digest algorithm properly (it is SHA-384, not the `ns2`
  prefix it appears as).
- **`attester.mjs`** — the evidence source behind **one interface, two implementations**.
  `StubAttester` synthesises correctly-shaped evidence today; `NvidiaAttester` throws with the precise
  blocker. **Moving to real silicon is a swap, not a rewrite** — only this file changes.
  Also holds `bindingNonce()`: the 32-byte seam carrying `H(signed prompt ‖ model measurement ‖ policy)`.
- **`verify.mjs`** — compares reported against golden. Returns a **stated depth, never a boolean**, and
  reports **coverage** — because a pass over 3 of 25 measurements is not the same claim as 25 of 25,
  and the record must say which.
- **`demo.mjs`** — the three cases above.

## What is still blocked, and it is small

Only one thing: **producing a real attestation report**, which needs the GPU's fused device key.
Everything downstream of it is built.

To finish without hardware we need two things from NVIDIA — both far smaller asks than a GPU:

1. **A sample NRAS-issued Entity Attestation Token** to develop against.
2. **Access to the NRAS JWKS** (`/v3/jwks` returns 403) so we can verify the token signature.

Endpoint status as observed 2026-09-10:

| Endpoint | Status |
|---|---|
| `rim.attestation.nvidia.com/v1/rim/ids` | **200 — public** |
| `rim.attestation.nvidia.com/v1/rim/{id}` | **200 — public** |
| `nras.attestation.nvidia.com/v3/attest/gpu` | 403 (needs valid evidence) |
| `nras.attestation.nvidia.com/v3/jwks` | 403 |

## How this gets used

1. **Now** — proves we consume NVIDIA's reference data correctly, and that the verifier detects
   tampering rather than merely claiming it would.
2. **With NVIDIA** — turns the ask from *"we would like to experiment"* into *"everything is built
   except the hardware step; here is exactly what we need."* See
   `rootz-attested-ai/prototype/ASK-nvidia-specific-question.md`.
3. **In production** — this *is* the evidence adapter for Origin Binder. The L2 rung of the L0–L3
   ladder stops being aspirational the day `NvidiaAttester` returns a real report.

Related: `../origin-binder.mjs` · `rootz-attested-ai/prototype/SPEC-nvidia-testbench-prototype.md`

---

## Validating that the build was not self-congratulatory

`demo.mjs` is **weak evidence and should not be trusted on its own.** `StubAttester` derives its
evidence *from* the reference set, so the happy case is tautological — a verifier that ignored its
inputs entirely and returned `PASS` would pass it. The demo shows the shape of the thing, not that the
thing works.

Two harnesses exist to catch that:

### `test.mjs` — 14 adversarial tests
Each asserts a property a cheating implementation breaks: all-wrong evidence must fail; **every**
single-measurement corruption must be caught (looped over all 25 active measurements, not just one);
empty evidence must not pass (vacuous truth); coverage must count what was *checked*, not what was
*supplied*; stub evidence can never exceed L0 however correct it is; hex case must normalise; a
truncated hash must not match; and evidence for one driver version must fail against another — with a
control test proving the two reference sets genuinely differ, so that cross-version test isn't vacuous.

### `mutate.mjs` — mutation testing, the check on the tests
Injects nine plausible bugs into `verify.mjs`, runs the suite against each, and reports which
**survive**. A surviving mutation means the code could be broken that way and nothing would notice.

```
node test.mjs      # 14 tests
node mutate.mjs    # 9/9 applied mutations killed
```

**Two real findings came out of this, and both were mine:**

1. **A wrong test.** The first depth assertion expected `L2-partial` on stub evidence. The code was
   right — stub is gated at L0 *before* coverage is considered — and the test was wrong. Split into
   two tests that check the ordering explicitly.
2. **A hole in the tests, found by mutation not inspection.** `coverage-counts-supplied` initially
   **survived**: the coverage test supplied exactly one measurement that was also checkable, so
   supplied and checked were both 1 and the mutation was invisible. Fixed by supplying four
   measurements of which only two are checkable. It now dies.

That second one is the whole argument for mutation testing: the test was *present*, *passing*, and
*not constraining the behaviour it named*.
