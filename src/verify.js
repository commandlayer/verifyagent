import { canonicalize } from './canonicalize.js';
import { resolveSignerFromEns } from './ens.js';

async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify a CommandLayer-style receipt.
 *
 * IMPORTANT: Signature verification below is intentionally a placeholder
 * for local demo use. It only compares against a demo marker value.
 * Do not treat this as production cryptographic verification.
 */
export async function verifyReceipt(receiptInput) {
  let receipt;
  try {
    receipt = typeof receiptInput === 'string' ? JSON.parse(receiptInput) : receiptInput;
  } catch {
    return invalidResult();
  }

  const expectedHash = receipt?.metadata?.proof?.hash_sha256;
  const canonicalization = receipt?.metadata?.proof?.canonicalization;

  const dataForHash = {
    signer: receipt?.signer,
    verb: receipt?.verb,
    input: receipt?.input,
    output: receipt?.output,
    execution: receipt?.execution,
    ts: receipt?.ts
  };

  const canonical = canonicalize(dataForHash);
  const recomputedHash = await sha256Hex(canonical);
  const hashMatches =
    canonicalization === 'json.sorted_keys.v1' &&
    typeof expectedHash === 'string' &&
    expectedHash === recomputedHash;

  const ens = await resolveSignerFromEns(receipt?.signer);

  // PLACEHOLDER ONLY: demo marker check, not real Ed25519 verification.
  const signature = receipt?.signature?.sig;
  const signatureValid = hashMatches && signature === 'DEMO_SIGNATURE_VALID_FOR_HASH';

  // For local demo, status is based on hash + signature checks only.
  // ENS remains a visible non-live check until real resolution is wired.
  const valid = hashMatches && signatureValid;

  return {
    valid,
    status: valid ? 'VERIFIED' : 'INVALID',
    checks: {
      hash_matches: hashMatches,
      signature_valid: signatureValid,
      ens_resolved: ens.ensResolved
    },
    ens,
    debug: {
      recomputed_hash_sha256: recomputedHash,
      signature_mode: 'placeholder'
    }
  };
}

function invalidResult() {
  return {
    valid: false,
    status: 'INVALID',
    checks: {
      hash_matches: false,
      signature_valid: false,
      ens_resolved: false
    },
    ens: {
      live: false,
      ensResolved: false,
      signer: 'unknown',
      keySource: 'ENS resolution not yet live in local demo',
      pubkey: null
    },
    debug: {
      recomputed_hash_sha256: null,
      signature_mode: 'placeholder'
    }
  };
}
