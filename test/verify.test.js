import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { computeReceiptHash, verifyReceipt } from '../src/verify.js';

const realReceiptPath = new URL('../test/fixtures/real-signed-receipt.json', import.meta.url);

async function loadRealReceipt() {
  return JSON.parse(await fs.readFile(realReceiptPath, 'utf8'));
}

function ensResolverFromFixture(fixture) {
  const records = fixture.ens_records;
  return async (_name, key) => records[key] || null;
}

test('valid real receipt verifies', async () => {
  const fixture = await loadRealReceipt();
  const result = await verifyReceipt(fixture.receipt, {
    ens: { textResolver: ensResolverFromFixture(fixture) }
  });

  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.checks.hash_matched, true);
  assert.equal(result.checks.signature_valid, true);
});

test('tampered receipt fails', async () => {
  const fixture = await loadRealReceipt();
  const tampered = structuredClone(fixture.receipt);
  tampered.output.summary = 'tampered output';

  const result = await verifyReceipt(tampered, {
    ens: { textResolver: ensResolverFromFixture(fixture) }
  });

  assert.equal(result.status, 'INVALID');
  assert.equal(result.checks.hash_matched, false);
});

test('DEMO_SIGNATURE_VALID_FOR_HASH is rejected', async () => {
  const fixture = await loadRealReceipt();
  const tampered = structuredClone(fixture.receipt);
  tampered.signature.sig = 'DEMO_SIGNATURE_VALID_FOR_HASH';

  const result = await verifyReceipt(tampered, {
    ens: { textResolver: ensResolverFromFixture(fixture) }
  });

  assert.equal(result.status, 'INVALID');
  assert.equal(result.checks.signature_valid, false);
});

test('hash changes when receipt content changes', async () => {
  const fixture = await loadRealReceipt();
  const before = await computeReceiptHash(fixture.receipt);
  const edited = structuredClone(fixture.receipt);
  edited.input.content = 'changed';
  const after = await computeReceiptHash(edited);

  assert.notEqual(before, after);
});
