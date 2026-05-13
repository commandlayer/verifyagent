import { canonicalize } from './canonicalize.js';
import { resolveSignerFromEns } from './ens.js';
import { importEd25519PublicKey, sha256Hex, verifyHashHexSignature, verifyCanonicalSignature } from './crypto.js';
import { detectReceiptMode, normalizeTrustVerb, validateClasTrustV1Shape, validateLegacyReceiptShape } from './schema.js';

export function canonicalReceiptPayload(receipt) {
  return {
    signer: receipt?.signer,
    verb: receipt?.verb,
    input: receipt?.input,
    output: receipt?.output,
    execution: receipt?.execution,
    ts: receipt?.ts
  };
}

// Extract proof fields from any supported receipt format.
// Priority order: metadata.proof (runtime), top-level proof (agent-sdk), legacy receipt.signature.
function extractProofFields(receipt) {
  const mp = receipt?.metadata?.proof;   // runtime format
  const tp = receipt?.proof;             // agent-sdk top-level proof
  const sig = receipt?.signature;        // legacy separate signature block

  // Canonical ID: prefer metadata.proof.canonical, accept legacy .canonicalization
  const canonical = mp?.canonical || mp?.canonicalization || tp?.canonical || null;

  // Hash: only present in legacy/runtime receipts (not agent-sdk v1.1.0)
  const hashSha256 = mp?.hash_sha256 || null;

  // Receipts WITHOUT hash_sha256 use raw canonical signing (v1.1.0 agent-sdk spec).
  // Receipts WITH hash_sha256 use legacy sha256-hex signing (runtime + wrapped-agent).
  const isV110 = !hashSha256;

  // Signature value: prefer metadata.proof.signature, then top-level proof, then legacy sig
  const signature = mp?.signature || mp?.signature_b64 || tp?.signature || sig?.sig || null;

  // Key ID
  const kid = mp?.kid || tp?.kid || sig?.kid || null;

  // Signer identity from receipt (multiple possible locations)
  const signerId = receipt?.signer || mp?.signer_id || tp?.signer_id || null;

  return { canonical, hashSha256, isV110, signature, kid, signerId };
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
      schema_valid: false,
      hash_matched: false,
      signature_valid: false,
      signer_resolved: false,
      signer_matched: false,
      trust_verb_identified: false,
      trust_verb: null
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

  const mode = detectReceiptMode(receipt);
  const schemaValid = mode === 'clas_v1'
    ? validateClasTrustV1Shape(receipt)
    : validateLegacyReceiptShape(receipt);

  // ENS resolution is required — no fallback keys exist.
  // If resolution fails, we cannot verify the receipt and must return INVALID immediately.
  const ens = await resolveSignerFromEns(receipt?.signer, options.ens || {});
  if (!ens.ensResolved) {
    return invalidResult({
      signerEns: receipt?.signer || 'unknown',
      publicKeySource: 'not resolved',
      checks: {
        schema_valid: schemaValid,
        hash_matched: false,
        signature_valid: false,
        signer_resolved: false,
        signer_matched: false,
        trust_verb_identified: false,
        trust_verb: null
      },
      error: 'ENS resolution failed — cannot verify without public key'
    });
  }

  const proof = extractProofFields(receipt);
  const payload = canonicalReceiptPayload(receipt);
  const canonical = canonicalize(payload);

  const signerResolved = Boolean(ens.records['cl.sig.pub'] && ens.records['cl.sig.kid']);

  // Signer identity: receipt's claimed signer must match ENS records.
  // Bug fix: this check is now included in the validity gate.
  const clReceiptSigner = ens.records['cl.receipt.signer'];
  const receiptSigner = receipt?.signer || receipt?.metadata?.proof?.signer_id || receipt?.proof?.signer_id;
  const signerMatched = clReceiptSigner
    ? receiptSigner === clReceiptSigner
    : Boolean(receiptSigner && receiptSigner === ens.signer);

  const expectedCanonical = ens.records['cl.sig.canonical'];
  const canonicalizationOk = proof.canonical === expectedCanonical;
  const keyIdMatches = proof.kid === ens.records['cl.sig.kid'];

  // Hash verification (legacy/runtime receipts that carry hash_sha256)
  let hashMatched = false;
  let recomputedHash = null;

  if (!proof.isV110) {
    // Legacy: recompute sha256 and compare
    recomputedHash = await sha256Hex(canonical);
    hashMatched = canonicalizationOk && typeof proof.hashSha256 === 'string' && proof.hashSha256 === recomputedHash;
  } else {
    // v1.1.0 (agent-sdk): no hash — canonical match + signature presence is the gate
    hashMatched = canonicalizationOk && Boolean(proof.signature);
  }

  const prefixedPub = ens.records['cl.sig.pub'];
  const pubkeyBase64 = typeof prefixedPub === 'string' ? prefixedPub.replace(/^ed25519:/, '') : null;

  let signatureValid = false;
  if (hashMatched && keyIdMatches && pubkeyBase64 && proof.signature) {
    try {
      const publicKey = await importEd25519PublicKey(pubkeyBase64);
      if (!proof.isV110 && recomputedHash) {
        // Legacy: Ed25519(UTF8(sha256_hex(canonical)))
        signatureValid = await verifyHashHexSignature(recomputedHash, proof.signature, publicKey);
      } else {
        // v1.1.0: Ed25519(UTF8(canonical))
        signatureValid = await verifyCanonicalSignature(canonical, proof.signature, publicKey);
      }
    } catch {
      signatureValid = false;
    }
  }

  const trustVerbCandidate = mode === 'clas_v1'
    ? (receipt?.verb ?? receipt?.metadata?.proof?.trust_verb ?? receipt?.metadata?.proof?.trustVerb)
    : (receipt?.metadata?.proof?.trust_verb ?? receipt?.metadata?.proof?.trustVerb ?? receipt?.verb);
  const trustVerb = normalizeTrustVerb(trustVerbCandidate);
  const trustVerbIdentified = trustVerb !== null;

  // signerMatched is now required for a receipt to be VERIFIED.
  // A receipt that declares the wrong signer must not pass.
  const valid = mode === 'clas_v1'
    ? schemaValid && hashMatched && signatureValid && signerMatched
    : hashMatched && signatureValid && signerMatched;

  return {
    valid,
    status: valid ? 'VERIFIED' : 'INVALID',
    signerEns: ens.records['cl.receipt.signer'] || receipt?.signer || 'unknown',
    keyId: ens.records['cl.sig.kid'] || null,
    publicKeySource: ens.keySource,
    canonicalization: proof.canonical || null,
    checks: {
      schema_valid: schemaValid,
      hash_matched: hashMatched,
      signature_valid: signatureValid,
      signer_resolved: signerResolved,
      signer_matched: signerMatched,
      trust_verb_identified: trustVerbIdentified,
      trust_verb: trustVerb
    },
    debug: {
      recomputed_hash_sha256: recomputedHash,
      expected_hash_sha256: proof.hashSha256 || null,
      key_id_matched: keyIdMatches
    }
  };
}

export function computeReceiptHash(receipt) {
  return sha256Hex(canonicalize(canonicalReceiptPayload(receipt)));
}
