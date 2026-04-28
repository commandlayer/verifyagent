import { canonicalize } from './canonicalize.js';
import { resolveSignerFromEns } from './ens.js';
import { importEd25519PublicKey, sha256Hex, verifyHashHexSignature } from './crypto.js';

function canonicalReceiptPayload(receipt) {
  return {
    signer: receipt?.signer,
    verb: receipt?.verb,
    input: receipt?.input,
    output: receipt?.output,
    execution: receipt?.execution,
    ts: receipt?.ts
  };
}

function invalidResult(overrides = {}) {
  return {
    valid: false,
    status: 'INVALID',
    signerEns: 'unknown',
    keyId: null,
    publicKeySource: 'not resolved',
    canonicalization: null,
    checks: {
      hash_matched: false,
      signature_valid: false
    },
    ...overrides
  };
}

export async function verifyReceipt(receiptInput, options = {}) {
  let receipt;
  try {
    receipt = typeof receiptInput === 'string' ? JSON.parse(receiptInput) : receiptInput;
  } catch {
    return invalidResult();
  }

  const ens = await resolveSignerFromEns(receipt?.signer, options.ens || {});
  const expectedHash = receipt?.metadata?.proof?.hash_sha256;
  const canonicalization = receipt?.metadata?.proof?.canonicalization;
  const payload = canonicalReceiptPayload(receipt);
  const canonical = canonicalize(payload);
  const recomputedHash = await sha256Hex(canonical);

  const expectedCanonical = ens.records['cl.sig.canonical'];
  const canonicalizationOk = canonicalization === expectedCanonical;
  const hashMatched = canonicalizationOk && typeof expectedHash === 'string' && expectedHash === recomputedHash;

  const keyIdMatches = receipt?.signature?.kid === ens.records['cl.sig.kid'];
  const prefixedPub = ens.records['cl.sig.pub'];
  const pubkeyBase64 = typeof prefixedPub === 'string' ? prefixedPub.replace(/^ed25519:/, '') : null;

  let signatureValid = false;
  if (hashMatched && keyIdMatches && pubkeyBase64 && receipt?.signature?.sig) {
    try {
      const publicKey = await importEd25519PublicKey(pubkeyBase64);
      signatureValid = await verifyHashHexSignature(recomputedHash, receipt.signature.sig, publicKey);
    } catch {
      signatureValid = false;
    }
  }

  const valid = hashMatched && signatureValid;
  return {
    valid,
    status: valid ? 'VERIFIED' : 'INVALID',
    signerEns: ens.records['cl.receipt.signer'] || receipt?.signer || 'unknown',
    keyId: ens.records['cl.sig.kid'] || null,
    publicKeySource: ens.keySource,
    canonicalization: canonicalization || null,
    checks: {
      hash_matched: hashMatched,
      signature_valid: signatureValid
    },
    debug: {
      recomputed_hash_sha256: recomputedHash,
      expected_hash_sha256: expectedHash || null,
      key_id_matched: keyIdMatches
    }
  };
}

export function computeReceiptHash(receipt) {
  return sha256Hex(canonicalize(canonicalReceiptPayload(receipt)));
}
