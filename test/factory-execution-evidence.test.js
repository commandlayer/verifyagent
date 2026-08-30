import test from 'node:test';
import assert from 'node:assert/strict';

import {
  FACTORY_EXECUTION_RECEIPT_PROFILE,
  isFactoryExecutionEvidenceReceipt,
  verifyFactoryExecutionEvidenceReceipt,
} from '../src/factory-execution-evidence.js';

const receipt = {
  receipt_id: 'rcpt_1',
  profile: FACTORY_EXECUTION_RECEIPT_PROFILE,
  issued_at: '2026-08-29T23:00:02.000Z',
  service: { service_id: 'researchagent', service_version: '0.1.0' },
  execution: {
    execution_id: 'exec_1',
    service_id: 'researchagent',
    service_version: '0.1.0',
    workflow_hash: `sha256:${'a'.repeat(64)}`,
  },
  proof: {
    alg: 'Ed25519',
    kid: 'kid-1',
    signer_id: 'runtime.commandlayer.eth',
    canonical: 'json.sorted_keys.v1',
    signature: 'test-signature',
  },
};

function ensResolver(name, key) {
  assert.equal(name, 'runtime.commandlayer.eth');
  return {
    'cl.sig.pub': 'ed25519:dGVzdA==',
    'cl.sig.kid': 'kid-1',
    'cl.sig.canonical': 'json.sorted_keys.v1',
    'cl.receipt.signer': 'runtime.commandlayer.eth',
  }[key] || null;
}

test('recognizes the Machine-Service Factory execution-evidence profile', () => {
  assert.equal(isFactoryExecutionEvidenceReceipt(receipt), true);
  assert.equal(isFactoryExecutionEvidenceReceipt({ profile: FACTORY_EXECUTION_RECEIPT_PROFILE }), false);
});

test('maps runtime-core verification into VerifyAgent semantics without claiming truth', async () => {
  let verifyCalls = 0;
  const runtimeCore = {
    parsePublicKey(value) {
      assert.equal(value, 'ed25519:dGVzdA==');
      return new Uint8Array(32);
    },
    async verifyFactoryExecutionReceipt(value, options) {
      verifyCalls += 1;
      assert.equal(value, receipt);
      assert.equal(options.expectedSigner, 'runtime.commandlayer.eth');
      assert.equal(options.expectedKid, 'kid-1');
      const key = await options.resolveKey({
        kid: 'kid-1',
        signerId: 'runtime.commandlayer.eth',
        alg: 'Ed25519',
      });
      assert.equal(key.kid, 'kid-1');
      return {
        valid: true,
        checks: {
          structureValid: true,
          profileValid: true,
          paymentFieldsAbsent: true,
          serviceBindingValid: true,
          timeOrderValid: true,
          algValid: true,
          canonicalValid: true,
          kidMatched: true,
          signerMatched: true,
          signatureValid: true,
        },
      };
    },
  };

  const result = await verifyFactoryExecutionEvidenceReceipt(receipt, {
    runtimeCore,
    ens: { textResolver: ensResolver },
  });
  assert.equal(verifyCalls, 1);
  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.valid, true);
  assert.equal(result.truth_certified, false);
  assert.equal(result.proof_scope, 'execution_integrity_and_provenance');
  assert.equal(result.checks.workflow_binding, true);
  assert.equal(result.checks.payment_separated, true);
});

test('fails indeterminate when runtime-core factory surface is not released yet', async () => {
  const result = await verifyFactoryExecutionEvidenceReceipt(receipt, {
    runtimeCore: {},
    ens: { textResolver: ensResolver },
  });
  assert.equal(result.valid, false);
  assert.equal(result.status, 'INDETERMINATE');
  assert.match(result.errors[0], /FACTORY_SURFACE_UNAVAILABLE/);
});

test('fails indeterminate when signer key cannot be resolved from ENS', async () => {
  const runtimeCore = {
    parsePublicKey() { return new Uint8Array(32); },
    async verifyFactoryExecutionReceipt(_value, options) {
      const key = await options.resolveKey({ kid: 'kid-1', signerId: 'runtime.commandlayer.eth', alg: 'Ed25519' });
      return {
        valid: false,
        checks: {
          structureValid: true,
          profileValid: true,
          paymentFieldsAbsent: true,
          serviceBindingValid: true,
          timeOrderValid: true,
          algValid: true,
          canonicalValid: true,
          kidMatched: true,
          signerMatched: true,
          signatureValid: false,
        },
        reason: key ? 'unexpected key' : 'No verification key available',
      };
    },
  };
  const result = await verifyFactoryExecutionEvidenceReceipt(receipt, {
    runtimeCore,
    ens: { textResolver: async () => null },
  });
  assert.equal(result.valid, false);
  assert.equal(result.status, 'INDETERMINATE');
  assert.equal(result.truth_certified, false);
});
