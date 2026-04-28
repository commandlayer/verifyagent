import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { canonicalize } from '../src/canonicalize.js';
import { sha256Hex, signHashHex } from '../src/crypto.js';
import { computeReceiptHash, verifyReceipt } from '../src/verify.js';

function payload(receipt) {
  return {
    signer: receipt.signer,
    verb: receipt.verb,
    input: receipt.input,
    output: receipt.output,
    execution: receipt.execution,
    ts: receipt.ts
  };
}

async function makeSigned(baseReceipt, keyPair) {
  const hash = await sha256Hex(canonicalize(payload(baseReceipt)));
  const sig = await signHashHex(hash, keyPair.privateKey);
  return {
    ...baseReceipt,
    metadata: { proof: { canonicalization: 'json.sorted_keys.v1', hash_sha256: hash } },
    signature: { alg: 'ed25519', kid: 'vC4WbcNoq2znSCiQ', sig }
  };
}

async function makeResolver(keyPair) {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const pub = Buffer.from(raw).toString('base64');
  return async (_name, key) => {
    const records = {
      'cl.sig.pub': `ed25519:${pub}`,
      'cl.sig.kid': 'vC4WbcNoq2znSCiQ',
      'cl.sig.canonical': 'json.sorted_keys.v1',
      'cl.receipt.signer': 'runtime.commandlayer.eth'
    };
    return records[key] || null;
  };
}

test('sample receipt verifies', async () => {
  const sample = JSON.parse(await fs.readFile(new URL('../examples/sample-receipt.json', import.meta.url), 'utf8'));
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const signed = await makeSigned(sample, keyPair);

  const result = await verifyReceipt(signed, { ens: { textResolver: await makeResolver(keyPair) } });
  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.checks.hash_matched, true);
  assert.equal(result.checks.signature_valid, true);
});

test('tampered receipt fails', async () => {
  const sample = JSON.parse(await fs.readFile(new URL('../examples/sample-receipt.json', import.meta.url), 'utf8'));
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const signed = await makeSigned(sample, keyPair);
  signed.output.summary = 'tampered output';

  const result = await verifyReceipt(signed, { ens: { textResolver: await makeResolver(keyPair) } });
  assert.equal(result.status, 'INVALID');
  assert.equal(result.checks.hash_matched, false);
});

test('DEMO_SIGNATURE_VALID_FOR_HASH is rejected', async () => {
  const sample = JSON.parse(await fs.readFile(new URL('../examples/sample-receipt.json', import.meta.url), 'utf8'));
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const signed = await makeSigned(sample, keyPair);
  signed.signature.sig = 'DEMO_SIGNATURE_VALID_FOR_HASH';

  const result = await verifyReceipt(signed, { ens: { textResolver: await makeResolver(keyPair) } });
  assert.equal(result.status, 'INVALID');
  assert.equal(result.checks.signature_valid, false);
});

test('canonical hash changes when receipt content is edited', async () => {
  const sample = JSON.parse(await fs.readFile(new URL('../examples/sample-receipt.json', import.meta.url), 'utf8'));
  const before = await computeReceiptHash(sample);
  sample.input.content = 'changed';
  const after = await computeReceiptHash(sample);
  assert.notEqual(before, after);
});
