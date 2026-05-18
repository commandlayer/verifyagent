import { resolveSignerFromEns } from './ens.js';
import { detectReceiptMode, normalizeTrustVerb, validateClasTrustV1Shape, validateLegacyReceiptShape } from './schema.js';
import * as runtimeCore from '@commandlayer/runtime-core';

const ED25519_SPKI_PREFIX_HEX = '302a300506032b6570032100';

function extractProofFields(receipt) {
  const proof = receipt?.metadata?.proof || {};
  return {
    canonical: proof?.canonicalization || null,
    hash: proof?.hash || null,
    signature: proof?.signature || null
  };
}

function invalidResult(overrides = {}) {
  return {
    valid: false,
    ok: false,
    status: 'INVALID',
    signerEns: 'unknown',
    keyId: null,
    publicKeySource: 'not resolved',
    canonicalization: null,
    checks: { schema: false, canonical_hash: false, signature: false, signer: false },
    ...overrides
  };
}

function mapRuntimeCoreError(error) {
  return error instanceof Error ? error.message : String(error || 'runtime-core verification failed');
}

function ensurePemFromEnsPub(ensPubValue) {
  const rawPublicKey = runtimeCore.parsePublicKey(ensPubValue);
  const der = Buffer.concat([Buffer.from(ED25519_SPKI_PREFIX_HEX, 'hex'), Buffer.from(rawPublicKey)]);
  const body = der.toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`;
}

export async function verifyReceipt(receiptInput, options = {}) {
  let receipt;
  try { receipt = typeof receiptInput === 'string' ? JSON.parse(receiptInput) : receiptInput; } catch { return invalidResult(); }

  const mode = detectReceiptMode(receipt);
  const schemaValid = mode === 'clas_v1' ? validateClasTrustV1Shape(receipt) : validateLegacyReceiptShape(receipt);
  const ens = await resolveSignerFromEns(receipt?.signer, options.ens || {});
  if (!ens.ensResolved) return invalidResult({ checks: { schema: schemaValid, canonical_hash: false, signature: false, signer: false }, error: 'ENS resolution failed — cannot verify without public key' });

  let runtime;
  try {
    const publicKeyPem = ensurePemFromEnsPub(ens.records?.['cl.sig.pub']);
    runtime = runtimeCore.verifyCommandLayerReceipt(receipt, {
      publicKeyPemOrDer: publicKeyPem,
      ensRecord: {
        signer: ens.records['cl.receipt.signer'] || ens.signer,
        kid: ens.records['cl.sig.kid'],
        canonical: ens.records['cl.sig.canonical'] || 'json.sorted_keys.v1'
      }
    });
  } catch (error) {
    const ensSigner = ens.records['cl.receipt.signer'] || ens.signer || null;
    runtime = {
      ok: false,
      status: 'INVALID',
      checks: {
        schema: false,
        canonical_hash: false,
        signature: false,
        signer: Boolean(ensSigner) && receipt?.signer === ensSigner
      },
      errors: [mapRuntimeCoreError(error)]
    };
  }

  const trustVerb = normalizeTrustVerb(receipt?.verb ?? receipt?.metadata?.proof?.trust_verb ?? receipt?.metadata?.proof?.trustVerb);
  const valid = schemaValid && runtime.checks.canonical_hash && runtime.checks.signature && runtime.checks.signer;

  return {
    valid, ok: valid, status: valid ? 'VERIFIED' : 'INVALID',
    signerEns: ens.records['cl.receipt.signer'] || receipt?.signer || 'unknown',
    keyId: ens.records['cl.sig.kid'] || null,
    publicKeySource: ens.keySource,
    canonicalization: extractProofFields(receipt).canonical,
    checks: { schema: schemaValid, canonical_hash: runtime.checks.canonical_hash, signature: runtime.checks.signature, signer: runtime.checks.signer, trust_verb_identified: trustVerb !== null, trust_verb: trustVerb },
    errors: runtime.errors || []
  };
}

export function computeReceiptHash(receipt) {
  const proof = runtimeCore.buildCanonicalProof(receipt);
  return proof.hash.value;
}
