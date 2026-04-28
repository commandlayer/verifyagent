import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { computeReceiptHash, verifyReceipt } from '../src/verify.js';
import { toBase64 } from '../src/crypto.js';
import { createSignedReceipt } from '../examples/wrapped-agent-demo/demo-agent.js';

const samplePath = new URL('../examples/sample-receipt.json', import.meta.url);
const tamperedPath = new URL('../examples/tampered-receipt.json', import.meta.url);

async function loadJson(pathUrl) {
  return JSON.parse(await fs.readFile(pathUrl, 'utf8'));
}

function bytesToPem(bytes) {
  const b64 = Buffer.from(bytes).toString('base64');
  const lines = b64.match(/.{1,64}/g)?.join('\n') || b64;
  return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----`;
}

test('sample receipt verifies', async () => {
  const sample = await loadJson(samplePath);
  const result = await verifyReceipt(sample);

  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.checks.hash_matched, true);
  assert.equal(result.checks.signature_valid, true);
});

test('tampered receipt fails verification', async () => {
  const tampered = await loadJson(tamperedPath);
  const result = await verifyReceipt(tampered);

  assert.equal(result.status, 'INVALID');
});

test('DEMO_SIGNATURE_VALID_FOR_HASH is rejected', async () => {
  const sample = await loadJson(samplePath);
  const mutated = structuredClone(sample);
  mutated.signature.sig = 'DEMO_SIGNATURE_VALID_FOR_HASH';

  const result = await verifyReceipt(mutated);

  assert.equal(result.status, 'INVALID');
  assert.equal(result.checks.signature_valid, false);
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
  assert.equal(result.checks.hash_matched, true);
  assert.equal(result.checks.signature_valid, true);
});
