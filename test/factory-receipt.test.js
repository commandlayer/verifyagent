import test from 'node:test';
import assert from 'node:assert/strict';
import * as runtimeCore from '@commandlayer/runtime-core';
import { verifyFactoryReceipt } from '../src/verify-factory.js';

function commercialEnvelope() {
  return {
    receipt_id: 'receipt_cross_repo_1',
    profile: 'commandlayer.execution-evidence.v1',
    issued_at: '2026-08-29T15:40:00.000Z',
    service: {
      service_id: 'researchagent',
      service_version: '0.1.0'
    },
    execution: {
      execution_id: 'exec_cross_repo_1',
      service_id: 'researchagent',
      service_version: '0.1.0',
      request_fingerprint: `sha256:${'a'.repeat(64)}`,
      input_hash: `sha256:${'b'.repeat(64)}`,
      output_hash: `sha256:${'c'.repeat(64)}`,
      started_at: '2026-08-29T15:39:58.000Z',
      completed_at: '2026-08-29T15:39:59.000Z',
      provider_steps: [],
      acceptance_checks: [],
      observed_state: null
    }
  };
}

test('Commercial-shaped factory receipt signs in runtime-core and verifies independently in VerifyAgent', async () => {
  const keys = runtimeCore.generateEd25519KeyPair();
  const signed = runtimeCore.signFactoryExecutionReceipt(commercialEnvelope(), {
    privateKeyPem: keys.privateKeyPem,
    kid: 'factory-roundtrip-key',
    signer: 'commandlayer:factory:test'
  });

  const result = await verifyFactoryReceipt(signed, {
    publicKeyPemOrDer: keys.publicKeyPem,
    publicKeySource: 'test fixture'
  });

  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.checks.schema, true);
  assert.equal(result.checks.signature, true);
  assert.equal(result.checks.signer, true);
  assert.equal(result.signer, 'commandlayer:factory:test');
  assert.equal(result.keyId, 'factory-roundtrip-key');
});

test('factory receipt verification does not require ENS or payment/settlement evidence', async () => {
  const keys = runtimeCore.generateEd25519KeyPair();
  const signed = runtimeCore.signFactoryExecutionReceipt(commercialEnvelope(), {
    privateKeyPem: keys.privateKeyPem,
    kid: 'rail-neutral-key',
    signer: 'did:key:rail-neutral-example'
  });

  assert.equal(Object.hasOwn(signed, 'settlement'), false);
  assert.equal(Object.hasOwn(signed, 'agent'), false);
  const result = await verifyFactoryReceipt(signed, { publicKeyPemOrDer: keys.publicKeyPem });
  assert.equal(result.status, 'VERIFIED');
});

test('VerifyAgent rejects tampered Commercial execution evidence', async () => {
  const keys = runtimeCore.generateEd25519KeyPair();
  const signed = runtimeCore.signFactoryExecutionReceipt(commercialEnvelope(), {
    privateKeyPem: keys.privateKeyPem,
    kid: 'factory-roundtrip-key',
    signer: 'commandlayer:factory:test'
  });
  const tampered = structuredClone(signed);
  tampered.execution.output_hash = `sha256:${'d'.repeat(64)}`;

  const result = await verifyFactoryReceipt(tampered, { publicKeyPemOrDer: keys.publicKeyPem });
  assert.equal(result.status, 'INVALID');
  assert.equal(result.checks.signature, false);
  assert(result.errors.includes('ERR_SIGNATURE_INVALID'));
});

test('VERIFIED explicitly remains an integrity/provenance claim rather than factual truth', async () => {
  const keys = runtimeCore.generateEd25519KeyPair();
  const signed = runtimeCore.signFactoryExecutionReceipt(commercialEnvelope(), {
    privateKeyPem: keys.privateKeyPem,
    kid: 'factory-roundtrip-key',
    signer: 'commandlayer:factory:test'
  });
  const result = await verifyFactoryReceipt(signed, { publicKeyPemOrDer: keys.publicKeyPem });
  assert.equal(result.status, 'VERIFIED');
  assert.match(result.copy.join(' '), /not factual truth/i);
});
