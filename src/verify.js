import { canonicalize } from './canonicalize.js';
import { resolveSignerFromEns } from './ens.js';
import { importEd25519PublicKey, sha256Hex, verifyHashHexSignature } from './crypto.js';
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
  const signerResolved = Boolean(ens.records['cl.sig.pub'] && ens.records['cl.sig.kid']);
  const signerMatched = Boolean(receipt?.signer && ens.records['cl.receipt.signer'] && receipt.signer === ens.records['cl.receipt.signer']);
  const trustVerbCandidate = mode === 'clas_v1'
    ? (receipt?.verb ?? receipt?.metadata?.proof?.trust_verb ?? receipt?.metadata?.proof?.trustVerb)
    : (receipt?.metadata?.proof?.trust_verb ?? receipt?.metadata?.proof?.trustVerb ?? receipt?.verb);
  const trustVerb = normalizeTrustVerb(trustVerbCandidate);
  const trustVerbIdentified = trustVerb !== null;
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

  const valid = mode === 'clas_v1'
    ? schemaValid && hashMatched && signatureValid
    : hashMatched && signatureValid;
  return {
    valid,
    status: valid ? 'VERIFIED' : 'INVALID',
    signerEns: ens.records['cl.receipt.signer'] || receipt?.signer || 'unknown',
    keyId: ens.records['cl.sig.kid'] || null,
    publicKeySource: ens.keySource,
    canonicalization: canonicalization || null,
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
      expected_hash_sha256: expectedHash || null,
      key_id_matched: keyIdMatches
    }
  };
}

export function computeReceiptHash(receipt) {
  return sha256Hex(canonicalize(canonicalReceiptPayload(receipt)));
}
