import test from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveFactoryKeyFromDocument,
  validateConfiguredUrl,
} from '../src/factory-key-document.js';
import {
  FACTORY_EXECUTION_RECEIPT_PROFILE,
  verifyFactoryExecutionEvidenceReceipt,
} from '../src/factory-execution-evidence.js';

const PUBLIC_KEY_PEM = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n';

function keyDocument(overrides = {}) {
  return {
    schema: 'commandlayer.receipt-verification-keys.v1',
    profile: 'commandlayer.execution-evidence.v1',
    keys: [{
      kid: 'kid-1',
      signer_id: 'commandlayer.org',
      alg: 'Ed25519',
      public_key_pem: PUBLIC_KEY_PEM,
      fingerprint: `sha256:${'a'.repeat(64)}`,
      status: 'active',
    }],
    secrets_included: false,
    ...overrides,
  };
}

function response(body, status = 200, headers = {}) {
  const normalized = new Map(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), String(value)]));
  return {
    status,
    headers: { get(name) { return normalized.get(String(name).toLowerCase()) || null; } },
    async text() { return typeof body === 'string' ? body : JSON.stringify(body); },
  };
}

function receipt() {
  return {
    receipt_id: 'rcpt_https_1',
    profile: FACTORY_EXECUTION_RECEIPT_PROFILE,
    issued_at: '2026-08-29T23:00:02.000Z',
    service: { service_id: 'researchagent', service_version: '0.1.0' },
    execution: {
      execution_id: 'exec_https_1',
      service_id: 'researchagent',
      service_version: '0.1.0',
      workflow_hash: `sha256:${'a'.repeat(64)}`,
    },
    proof: {
      alg: 'Ed25519',
      kid: 'kid-1',
      signer_id: 'commandlayer.org',
      canonical: 'json.sorted_keys.v1',
      signature: 'test-signature',
    },
  };
}

test('factory key URL is configuration-only HTTPS without credentials/fragments', () => {
  assert.equal(validateConfiguredUrl('https://api.commandlayer.org/.well-known/commandlayer-receipt-keys'), 'https://api.commandlayer.org/.well-known/commandlayer-receipt-keys');
  assert.throws(() => validateConfiguredUrl('http://api.commandlayer.org/keys'), /HTTPS/);
  assert.throws(() => validateConfiguredUrl('https://user:pass@example.com/keys'), /credentials/);
  assert.throws(() => validateConfiguredUrl('https://example.com/keys#fragment'), /fragment/);
});

test('resolves exact active kid and signer from canonical HTTPS key document', async () => {
  let requested;
  const result = await resolveFactoryKeyFromDocument({ kid: 'kid-1', signerId: 'commandlayer.org' }, {
    url: 'https://api.commandlayer.org/.well-known/commandlayer-receipt-keys',
    fetchImpl: async (url, options) => {
      requested = { url, options };
      return response(keyDocument(), 200, { 'content-length': '500' });
    },
  });
  assert.equal(result.state, 'resolved');
  assert.equal(result.key.kid, 'kid-1');
  assert.equal(result.key.signerId, 'commandlayer.org');
  assert.equal(result.key.publicKeyPem, PUBLIC_KEY_PEM);
  assert.equal(result.source, 'CommandLayer HTTPS trust root');
  assert.equal(requested.options.redirect, 'error');
  assert.equal(requested.options.method, 'GET');
});

test('reachable trust root with missing key is authoritative and cannot be treated as unavailable', async () => {
  const result = await resolveFactoryKeyFromDocument({ kid: 'other-kid', signerId: 'commandlayer.org' }, {
    url: 'https://api.commandlayer.org/.well-known/commandlayer-receipt-keys',
    fetchImpl: async () => response(keyDocument()),
  });
  assert.equal(result.state, 'authoritative_failure');
  assert.equal(result.reason, 'ERR_FACTORY_KEY_NOT_FOUND');
});

test('network/HTTP unavailability is eligible for identity fallback', async () => {
  const network = await resolveFactoryKeyFromDocument({ kid: 'kid-1', signerId: 'commandlayer.org' }, {
    url: 'https://api.commandlayer.org/.well-known/commandlayer-receipt-keys',
    fetchImpl: async () => { throw new Error('offline'); },
  });
  assert.equal(network.state, 'unavailable');

  const unavailable = await resolveFactoryKeyFromDocument({ kid: 'kid-1', signerId: 'commandlayer.org' }, {
    url: 'https://api.commandlayer.org/.well-known/commandlayer-receipt-keys',
    fetchImpl: async () => response('', 503),
  });
  assert.equal(unavailable.state, 'unavailable');
});

test('oversized or private-key-bearing trust documents fail closed', async () => {
  const oversized = await resolveFactoryKeyFromDocument({ kid: 'kid-1', signerId: 'commandlayer.org' }, {
    url: 'https://api.commandlayer.org/.well-known/commandlayer-receipt-keys',
    maxBytes: 10,
    fetchImpl: async () => response(keyDocument(), 200, { 'content-length': '500' }),
  });
  assert.equal(oversized.state, 'authoritative_failure');
  assert.equal(oversized.reason, 'ERR_FACTORY_KEY_DOCUMENT_TOO_LARGE');

  const privateDoc = keyDocument();
  privateDoc.keys[0].public_key_pem = '-----BEGIN PRIVATE KEY-----\nforbidden\n-----END PRIVATE KEY-----';
  const privateResult = await resolveFactoryKeyFromDocument({ kid: 'kid-1', signerId: 'commandlayer.org' }, {
    url: 'https://api.commandlayer.org/.well-known/commandlayer-receipt-keys',
    fetchImpl: async () => response(privateDoc),
  });
  assert.equal(privateResult.state, 'authoritative_failure');
  assert.equal(privateResult.reason, 'ERR_FACTORY_PUBLIC_KEY_INVALID');
});

test('VerifyAgent prefers configured HTTPS trust root without calling ENS', async () => {
  let ensCalls = 0;
  const runtimeCore = {
    async verifyFactoryExecutionReceipt(_receipt, options) {
      const key = await options.resolveKey({ kid: 'kid-1', signerId: 'commandlayer.org', alg: 'Ed25519' });
      assert.equal(key.publicKeyPem, PUBLIC_KEY_PEM);
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
  const result = await verifyFactoryExecutionEvidenceReceipt(receipt(), {
    runtimeCore,
    keyDocument: {
      url: 'https://api.commandlayer.org/.well-known/commandlayer-receipt-keys',
      fetchImpl: async () => response(keyDocument()),
    },
    ens: { textResolver: async () => { ensCalls += 1; return null; } },
  });
  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.publicKeySource, 'CommandLayer HTTPS trust root');
  assert.equal(ensCalls, 0);
});

test('VerifyAgent does not bypass authoritative HTTPS key mismatch via ENS', async () => {
  let ensCalls = 0;
  const runtimeCore = {
    parsePublicKey() { return new Uint8Array(32); },
    async verifyFactoryExecutionReceipt(_receipt, options) {
      const key = await options.resolveKey({ kid: 'kid-1', signerId: 'commandlayer.org', alg: 'Ed25519' });
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
  const wrong = keyDocument();
  wrong.keys[0].kid = 'different-kid';
  const result = await verifyFactoryExecutionEvidenceReceipt(receipt(), {
    runtimeCore,
    keyDocument: {
      url: 'https://api.commandlayer.org/.well-known/commandlayer-receipt-keys',
      fetchImpl: async () => response(wrong),
    },
    ens: { textResolver: async () => { ensCalls += 1; return 'ed25519:dGVzdA=='; } },
  });
  assert.equal(result.status, 'INDETERMINATE');
  assert.equal(result.errors[0], 'ERR_FACTORY_KEY_NOT_FOUND');
  assert.equal(ensCalls, 0);
});
