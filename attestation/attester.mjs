// attester.mjs — the evidence source, behind one interface.
//
// TWO IMPLEMENTATIONS, ONE SHAPE. Everything downstream (verification, binding,
// the receipt) is written against this interface, so moving from stub to real
// silicon is a SWAP, not a rewrite. That is the whole point of building now:
// when NVIDIA provides hardware or a sample token, only this file changes.
//
//   StubAttester   — synthesises evidence shaped like the real thing. No GPU.
//   NvidiaAttester — calls NVAT / nvtrust locally, or NRAS remotely. NOT YET BUILT.

import { createHash, randomBytes } from 'crypto';

/**
 * @typedef {Object} Evidence
 * @property {string}   nonce         32-byte hex — the seam we bind through
 * @property {string}   deviceId      claimed device identity
 * @property {string}   driverVersion maps to a RIM id
 * @property {string}   architecture
 * @property {boolean}  ccMode        confidential-computing mode active
 * @property {Array<{index:number,value:string}>} measurements what the device REPORTS
 * @property {string}   source        'stub' | 'nvat-local' | 'nras'
 * @property {string}   collectedAt
 */

export class StubAttester {
  /**
   * @param {object} opts
   * @param {object} opts.referenceSet a parsed RIM — the stub reports these values,
   *                 so a clean run VERIFIES and we can then perturb one to prove
   *                 the verifier actually detects a mismatch.
   */
  constructor({ referenceSet }) {
    this.ref = referenceSet;
    this.source = 'stub';
  }

  /** @param {string} nonceHex 32 bytes hex — carries our application evidence hash */
  async collect(nonceHex) {
    if (!/^[0-9a-f]{64}$/i.test(nonceHex)) throw new Error('nonce must be 32 bytes hex');
    return {
      nonce: nonceHex.toLowerCase(),
      deviceId: 'STUB-' + createHash('sha256').update(this.ref.id).digest('hex').slice(0, 16),
      driverVersion: (this.ref.id.match(/_(\d[\d.]+)$/) || [, 'unknown'])[1],
      architecture: this.ref.identity?.name || 'unknown',
      ccMode: true,
      measurements: this.ref.measurements
        .filter(m => m.active)
        .map(m => ({ index: m.index, value: m.value })),
      source: 'stub',
      collectedAt: new Date().toISOString(),
      _stubWarning: 'SYNTHETIC EVIDENCE — not signed by any device key. Development only.',
    };
  }
}

export class NvidiaAttester {
  constructor({ mode = 'nras' } = {}) { this.mode = mode; this.source = mode; }
  async collect(_nonceHex) {
    throw new Error(
      'NvidiaAttester not implemented — blocked on: (a) CC-mode hardware with the ' +
      'attestation path exposed, or (b) a sample NRAS-issued EAT plus JWKS access ' +
      'to verify its signature. See prototype/ASK-nvidia-specific-question.md.'
    );
  }
}

/** 32-byte nonce carrying our application-layer commitment — THE BINDING SEAM. */
export function bindingNonce({ signedPromptHash, modelMeasurement, policyId }) {
  return createHash('sha256')
    .update(signedPromptHash).update('\x00')
    .update(modelMeasurement).update('\x00')
    .update(policyId || '')
    .digest('hex');
}

export function randomNonce() { return randomBytes(32).toString('hex'); }
