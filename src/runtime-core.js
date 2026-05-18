import { canonicalize } from './canonicalize.js';
import { canonicalReceiptPayload } from './receipt-payload.js';
import { importEd25519PublicKey, sha256Hex, verifyHashHexSignature } from './crypto.js';

export const CANONICAL_METHOD = 'json.sorted_keys.v1';
export const SIGNATURE_ALG = 'Ed25519';

export async function verifyCommandLayerReceipt(receipt, authority = {}) {
  const proof = receipt?.metadata?.proof;
  const canonicalMethodOk = proof?.canonicalization === CANONICAL_METHOD;
  const hashAlgOk = proof?.hash?.alg === 'SHA-256';
  const sigAlgOk = proof?.signature?.alg === SIGNATURE_ALG;
  const signerOk = !authority.requiredSigner || receipt?.signer === authority.requiredSigner;
  const kidOk = !authority.kid || proof?.signature?.kid === authority.kid;

  const canonical = canonicalize(canonicalReceiptPayload(receipt));
  const recomputedHash = await sha256Hex(canonical);
  const hashOk = canonicalMethodOk && hashAlgOk && proof?.hash?.value === recomputedHash;

  let signatureOk = false;
  if (hashOk && sigAlgOk && authority.pubkeyBase64 && typeof proof?.signature?.value === 'string') {
    try {
      const pub = await importEd25519PublicKey(authority.pubkeyBase64);
      signatureOk = await verifyHashHexSignature(recomputedHash, proof.signature.value, pub);
    } catch {
      signatureOk = false;
    }
  }

  return {
    ok: canonicalMethodOk && hashOk && signatureOk && signerOk && kidOk,
    checks: {
      canonical_hash: hashOk,
      signature: signatureOk,
      signer: signerOk && kidOk
    },
    debug: { recomputedHash }
  };
}
