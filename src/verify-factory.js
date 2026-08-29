import * as runtimeCore from '@commandlayer/runtime-core';

function invalidFactoryResult(errors = []) {
  return {
    valid: false,
    ok: false,
    status: 'INVALID',
    signer: 'unknown',
    keyId: null,
    publicKeySource: 'not resolved',
    canonicalization: null,
    checks: {
      schema: false,
      canonical_payload: false,
      signature: false,
      signer: false,
      factory_execution_receipt: true
    },
    errors
  };
}

/**
 * Verify CommandLayer's rail-neutral Machine-Service Factory execution receipt.
 *
 * The verification key is supplied through an adapter-neutral option:
 * - publicKeyPemOrDer
 * - publicKeysByKid
 * - resolvePublicKey(proof)
 *
 * ENS, ERC-8004, x402 and settlement fields are deliberately not required.
 * A VERIFIED result proves canonical payload integrity/signature provenance for
 * the execution envelope; it does not prove the output is factually true.
 */
export async function verifyFactoryReceipt(receiptInput, options = {}) {
  let receipt;
  try {
    receipt = typeof receiptInput === 'string' ? JSON.parse(receiptInput) : receiptInput;
  } catch {
    return invalidFactoryResult(['ERR_MALFORMED_RECEIPT']);
  }

  if (typeof runtimeCore.verifyFactoryExecutionReceipt !== 'function') {
    return invalidFactoryResult(['ERR_RUNTIME_CORE_FACTORY_PROFILE_UNAVAILABLE']);
  }

  let result;
  try {
    result = runtimeCore.verifyFactoryExecutionReceipt(receipt, options);
  } catch (error) {
    return invalidFactoryResult([error instanceof Error ? error.message : String(error)]);
  }

  const proof = receipt?.proof;
  const profileMatches = receipt?.profile === runtimeCore.FACTORY_EXECUTION_RECEIPT_PROFILE;
  const signerPresent = typeof proof?.signer === 'string' && proof.signer.trim().length > 0;
  const valid = Boolean(result.ok && profileMatches && signerPresent);

  return {
    valid,
    ok: valid,
    status: valid ? 'VERIFIED' : 'INVALID',
    signer: proof?.signer || 'unknown',
    signerEns: proof?.signer || 'unknown',
    keyId: proof?.signature?.kid || null,
    publicKeySource: options.publicKeySource || 'factory key resolver',
    canonicalization: proof?.canonicalization || null,
    checks: {
      schema: profileMatches,
      canonical_payload: true,
      signature: Boolean(result.signature_valid),
      signer: signerPresent,
      factory_execution_receipt: true
    },
    proofCard: {
      type: 'execution',
      signer: proof?.signer || 'unknown',
      covered_fields: Array.isArray(result.covered) ? result.covered : [],
      signature_valid: Boolean(result.signature_valid),
      status: result.ok ? 'valid' : 'invalid'
    },
    copy: [
      'Execution evidence verified cryptographically.',
      'Verification establishes integrity and provenance, not factual truth.'
    ],
    errors: Array.isArray(result.errors) ? result.errors : []
  };
}
