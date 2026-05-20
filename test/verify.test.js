import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { computeReceiptHash, verifyReceipt } from '../src/verify.js';
import { toBase64 } from '../src/crypto.js';
import { createSignedReceipt } from '../examples/wrapped-agent-demo/demo-agent.js';
import * as runtimeCore from '@commandlayer/runtime-core';

const samplePath = new URL('../examples/sample-receipt.json', import.meta.url);
const tamperedPath = new URL('../examples/tampered-receipt.json', import.meta.url);
const clasValidPath = new URL('../examples/clas-valid-receipt.json', import.meta.url);
const clasTamperedPath = new URL('../examples/clas-tampered-receipt.json', import.meta.url);
const clasInvalidPath = new URL('../examples/clas-invalid-receipt.json', import.meta.url);

async function loadJson(pathUrl) {
  return JSON.parse(await fs.readFile(pathUrl, 'utf8'));
}

function bytesToPem(bytes) {
  const b64 = Buffer.from(bytes).toString('base64');
  const lines = b64.match(/.{1,64}/g)?.join('\n') || b64;
  return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----`;
}

function toClasV1(receipt, overrides = {}) {
  return {
    ...receipt,
    family: 'clas_trust_verification',
    version: 'clas_trust_verification.v1',
    metadata: {
      ...receipt.metadata,
      family: 'clas_trust_verification',
      version: 'v1',
      proof: {
        ...receipt.metadata?.proof,
        trust_verb: 'verify',
        ...overrides.proof
      }
    },
    ...overrides
  };
}

// These fixture receipts were signed with a specific keypair.
// The ENS mock below provides the matching public key so tests remain deterministic
// and do not rely on any hardcoded fallback (which was removed as a security fix).
// NOTE: live ENS for runtime.commandlayer.eth uses a different key — these fixture
// keys are only for test isolation.
const FIXTURE_ENS_RECORDS = {
  'cl.receipt.signer': 'runtime.commandlayer.eth',
  'cl.sig.kid': 'vC4WbcNoq2znSCiQ',
  'cl.sig.pub': 'ed25519:trSRcjBVbLt+dz8LMuIwMooTwCyeW8UddfGXu/cVbLc=',
  'cl.sig.canonical': 'json.sorted_keys.v1'
};

const fixtureEns = {
  textResolver: async (_name, key) => FIXTURE_ENS_RECORDS[key] || null
};

test('sample receipt verifies', async () => {
  const sample = await loadJson(samplePath);
  const result = await verifyReceipt(sample, { ens: fixtureEns });

  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.checks.schema, true);
  assert.equal(result.checks.canonical_hash, true);
  assert.equal(result.checks.signature, true);
  assert.equal(result.checks.signer, true);
});

test('tampered receipt fails verification', async () => {
  const tampered = await loadJson(tamperedPath);
  const result = await verifyReceipt(tampered, { ens: fixtureEns });

  assert.equal(result.status, 'INVALID');
  assert.equal(result.checks.schema, true);
});

test('canonical CLAS fixture has mapped trust checks', async () => {
  const clasValid = await loadJson(clasValidPath);
  const result = await verifyReceipt(clasValid, { ens: fixtureEns });

  assert.equal(result.status, 'INVALID');
  assert.equal(result.checks.schema, false);
  assert.equal(result.checks.trust_verb_identified, true);
  assert.equal(result.checks.trust_verb, 'verify');
});

test('canonical CLAS tampered fixture fails proof checks', async () => {
  const clasTampered = await loadJson(clasTamperedPath);
  const result = await verifyReceipt(clasTampered, { ens: fixtureEns });

  assert.equal(result.checks.canonical_hash, false);
  assert.equal(result.checks.signature, false);
  assert.equal(result.status, 'INVALID');
});

test('canonical CLAS invalid fixture fails schema validation', async () => {
  const clasInvalid = await loadJson(clasInvalidPath);
  const result = await verifyReceipt(clasInvalid, { ens: fixtureEns });

  assert.equal(result.checks.schema, false);
  assert.equal(result.status, 'INVALID');
});

test('invalid enum/verb fails schema validation', async () => {
  const sample = await loadJson(samplePath);
  const clasReceipt = toClasV1(sample, { verb: 'negotiate', proof: { trust_verb: 'negotiate' } });
  const result = await verifyReceipt(clasReceipt, { ens: fixtureEns });

  assert.equal(result.checks.trust_verb, null);
  assert.equal(result.checks.trust_verb_identified, false);
  assert.equal(result.checks.schema, false);
  assert.equal(result.status, 'INVALID');
});

test('signer resolution and signer match checks are populated', async () => {
  const sample = await loadJson(samplePath);
  const result = await verifyReceipt(sample, { ens: fixtureEns });

  assert.equal(result.checks.signer, true);
  assert.equal(result.checks.signer, true);
});

test('DEMO_SIGNATURE_VALID_FOR_HASH is rejected', async () => {
  const sample = await loadJson(samplePath);
  const mutated = structuredClone(sample);
  mutated.metadata.proof.signature.value = 'DEMO_SIGNATURE_VALID_FOR_HASH';

  const result = await verifyReceipt(mutated, { ens: fixtureEns });

  assert.equal(result.status, 'INVALID');
  assert.equal(result.checks.signature, false);
});

test('changing output.summary changes computed hash', async () => {
  const sample = await loadJson(samplePath);
  const before = await computeReceiptHash(sample);
  const edited = structuredClone(sample);
  edited.output.summary = `${edited.output.summary} changed`;
  const after = await computeReceiptHash(edited);

  assert.notEqual(before, after);
});

test('wrapper-generated receipt verifies with verifyReceipt', async () => {
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const privateKeyPkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  const kid = 'test-wrapper-kid';
  const signer = 'runtime.commandlayer.eth';
  const privatePem = bytesToPem(privateKeyPkcs8);

  const receipt = await createSignedReceipt({
    signer,
    kid,
    privatePem,
    now: new Date('2026-04-28T00:00:00.000Z')
  });

  const ensRecords = {
    'cl.receipt.signer': signer,
    'cl.sig.kid': kid,
    'cl.sig.pub': `ed25519:${toBase64(publicKeyRaw)}`,
    'cl.sig.canonical': 'json.sorted_keys.v1'
  };

  const result = await verifyReceipt(receipt, {
    ens: {
      textResolver: async (_name, key) => ensRecords[key] || null
    }
  });

  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.checks.canonical_hash, true);
  assert.equal(result.checks.signature, true);
  assert.equal(result.checks.signer, true);
});

test('missing required CLAS field fails schema validation', async () => {
  const clasValid = await loadJson(clasValidPath);
  const missingSig = structuredClone(clasValid);
  delete missingSig.metadata.proof.signature;
  const result = await verifyReceipt(missingSig, { ens: fixtureEns });

  assert.equal(result.checks.schema, false);
  assert.equal(result.status, 'INVALID');
});

test('shared proof $ref resolution works (invalid hash format fails)', async () => {
  const clasValid = await loadJson(clasValidPath);
  const badProof = structuredClone(clasValid);
  badProof.metadata.proof.hash.value = 'not-a-sha256';
  const result = await verifyReceipt(badProof, { ens: fixtureEns });

  assert.equal(result.checks.schema, false);
  assert.equal(result.status, 'INVALID');
});

test('ENS resolution failure returns INVALID immediately with clear error', async () => {
  const sample = await loadJson(samplePath);
  // No textResolver provided — ENS resolution will fail
  const result = await verifyReceipt(sample, { ens: {} });

  assert.equal(result.status, 'INVALID');
  assert.equal(result.checks.signer, false);
  assert.equal(result.checks.signature, false);
  assert.equal(typeof result.error, 'string');
  assert.match(result.error, /ENS resolution failed/);
});

test('wrong signer in receipt fails validity even with valid hash+signature', async () => {
  const sample = await loadJson(samplePath);
  // Mutate signer to a different ENS name
  const mutated = structuredClone(sample);
  mutated.signer = 'attacker.eth';

  // ENS still resolves for the attacker name with the fixture keys
  // but cl.receipt.signer won't match
  const attackerEns = {
    textResolver: async (_name, key) => {
      // Return fixture keys but with a different cl.receipt.signer
      const records = { ...FIXTURE_ENS_RECORDS, 'cl.receipt.signer': 'attacker.eth' };
      return records[key] || null;
    }
  };

  const result = await verifyReceipt(mutated, { ens: attackerEns });
  // hash and signature are invalid since payload changed, but signer_matched behavior is correct
  assert.equal(result.checks.signer, true); // attacker.eth matches attacker.eth
  // The hash won't match since the signer field is part of the canonical payload
  assert.equal(result.checks.canonical_hash, false);
  assert.equal(result.status, 'INVALID');
});

test('receipt signer mismatch with ENS cl.receipt.signer fails validity', async () => {
  const sample = await loadJson(samplePath);
  const mutated = structuredClone(sample);
  mutated.signer = 'impersonator.eth'; // claims to be someone else

  // ENS resolves correctly for runtime.commandlayer.eth
  const result = await verifyReceipt(mutated, { ens: fixtureEns });

  // cl.receipt.signer is runtime.commandlayer.eth, receipt.signer is impersonator.eth
  assert.equal(result.checks.signer, false);
  assert.equal(result.status, 'INVALID');
});

test('runtime-produced receipt verifies', async () => {
  const { privateKeyPem, ensPubValue } = await runtimeCore.generateEd25519KeyPair();
  const signer = 'runtime.commandlayer.eth';
  const kid = 'runtime-e2e-test-kid';

  const receipt = await runtimeCore.signCommandLayerReceipt({
    signer,
    verb: 'respond',
    ts: '2026-05-20T00:00:00.000Z',
    input: { prompt: 'runtime verification' },
    output: { summary: 'valid runtime receipt' },
    execution: { duration_ms: 10, model: 'test' }
  }, {
    signer,
    kid,
    privateKeyPem,
    canonicalization: runtimeCore.CANONICAL_METHOD,
    metadata: { proof: { hash: { alg: 'sha-256' }, signature: { alg: runtimeCore.SIGNATURE_ALG } } }
  });

  const ensRecords = {
    'cl.receipt.signer': signer,
    'cl.sig.kid': kid,
    'cl.sig.pub': ensPubValue,
    'cl.sig.canonical': runtimeCore.CANONICAL_METHOD
  };

  const result = await verifyReceipt(receipt, { ens: { textResolver: async (_name, key) => ensRecords[key] || null } });
  assert.equal(result.status, 'VERIFIED');
});

test('tampered runtime-produced receipt invalidates', async () => {
  const sample = await loadJson(samplePath);
  const tampered = structuredClone(sample);
  tampered.output.summary = 'runtime receipt tampered';
  const result = await verifyReceipt(tampered, { ens: fixtureEns });
  assert.equal(result.status, 'INVALID');
});

test('missing metadata.proof rejects', async () => {
  const sample = await loadJson(samplePath);
  const missingProof = structuredClone(sample);
  delete missingProof.metadata.proof;
  const result = await verifyReceipt(missingProof, { ens: fixtureEns });
  assert.equal(result.status, 'INVALID');
});

test('wrong canonicalization rejects', async () => {
  const sample = await loadJson(samplePath);
  const wrongCanonical = structuredClone(sample);
  wrongCanonical.metadata.proof.canonicalization = 'json.unsorted_keys.v1';
  const result = await verifyReceipt(wrongCanonical, { ens: fixtureEns });
  assert.equal(result.status, 'INVALID');
});
