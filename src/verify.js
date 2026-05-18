import { canonicalize } from './canonicalize.js';
import { resolveSignerFromEns } from './ens.js';
import { sha256Hex } from './crypto.js';
import { detectReceiptMode, normalizeTrustVerb, validateClasTrustV1Shape, validateLegacyReceiptShape } from './schema.js';
import { verifyCommandLayerReceipt } from '@commandlayer/runtime-core';
import { canonicalReceiptPayload } from './receipt-payload.js';

// Extract proof fields from any supported receipt format.
// Priority order: metadata.proof (runtime), top-level proof (agent-sdk), legacy receipt.signature.
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

export async function verifyReceipt(receiptInput, options = {}) {
  let receipt;
  try { receipt = typeof receiptInput === 'string' ? JSON.parse(receiptInput) : receiptInput; } catch { return invalidResult(); }

  const mode = detectReceiptMode(receipt);
  const schemaValid = mode === 'clas_v1' ? validateClasTrustV1Shape(receipt) : validateLegacyReceiptShape(receipt);
  const ens = await resolveSignerFromEns(receipt?.signer, options.ens || {});
  if (!ens.ensResolved) return invalidResult({ checks: { schema: schemaValid, canonical_hash: false, signature: false, signer: false }, error: 'ENS resolution failed — cannot verify without public key' });

  let runtime;
  try {
    runtime = verifyCommandLayerReceipt(receipt, {
      publicKeyPemOrDer: ens.publicKeyPem || ens.pubkeyPem || ens.publicKey || ens.records?.['cl.sig.pub'] || '',
      ensRecord: {
        signer: ens.records['cl.receipt.signer'] || ens.signer,
        kid: ens.records['cl.sig.kid'],
        canonical: ens.records['cl.sig.canonical'] || 'json.sorted_keys.v1'
      }
    });
  } catch (error) {
    runtime = {
      ok: false,
      status: 'INVALID',
      checks: { schema: false, canonical_hash: false, signature: false, signer: false },
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
  return sha256Hex(canonicalize(canonicalReceiptPayload(receipt)));
}
