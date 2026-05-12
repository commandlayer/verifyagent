const TRUST_VERBS = new Set([
  'verify',
  'authenticate',
  'authorize',
  'attest',
  'sign',
  'permit',
  'grant',
  'approve',
  'reject',
  'endorse'
]);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasString(value) {
  return typeof value === 'string' && value.length > 0;
}

export function detectReceiptMode(receipt) {
  if (!isObject(receipt)) return 'legacy';

  const metadata = receipt.metadata;
  const proof = metadata?.proof;

  const clasIndicators = [
    receipt?.version === '1.0.0',
    receipt?.family === 'trust-verification',
    receipt?.version === 'clas_trust_verification.v1',
    receipt?.family === 'clas_trust_verification',
    metadata?.family === 'trust-verification',
    metadata?.version === '1.0.0',
    metadata?.family === 'clas_trust_verification',
    metadata?.version === 'v1',
    normalizeTrustVerb(receipt?.verb) !== null,
    hasString(proof?.trust_verb),
    hasString(proof?.trustVerb),
    isObject(proof?.trust)
  ];

  return clasIndicators.some(Boolean) ? 'clas_v1' : 'legacy';
}

export function validateLegacyReceiptShape(receipt) {
  if (!isObject(receipt)) return false;

  return hasString(receipt.signer)
    && isObject(receipt.metadata)
    && isObject(receipt.metadata.proof)
    && hasString(receipt.metadata.proof.canonicalization)
    && hasString(receipt.metadata.proof.hash_sha256)
    && isObject(receipt.signature)
    && hasString(receipt.signature.alg)
    && hasString(receipt.signature.kid)
    && hasString(receipt.signature.sig);
}

export function validateClasTrustV1Shape(receipt) {
  if (!validateLegacyReceiptShape(receipt)) return false;

  const metadata = receipt.metadata;
  const proof = metadata?.proof;
  const versionOk = receipt?.version === '1.0.0'
    || metadata?.version === '1.0.0'
    || receipt?.version === 'clas_trust_verification.v1'
    || metadata?.version === 'v1';
  const familyOk = receipt?.family === 'trust-verification'
    || metadata?.family === 'trust-verification'
    || receipt?.family === 'clas_trust_verification'
    || metadata?.family === 'clas_trust_verification';

  return versionOk && familyOk && (
    normalizeTrustVerb(receipt?.verb) !== null
    || normalizeTrustVerb(proof?.trust_verb) !== null
    || normalizeTrustVerb(proof?.trustVerb) !== null
    || hasString(proof?.trust_verb)
    || hasString(proof?.trustVerb)
    || isObject(proof?.trust)
  );
}

export function normalizeTrustVerb(verb) {
  if (typeof verb !== 'string') return null;
  const normalized = verb.trim().toLowerCase();
  return TRUST_VERBS.has(normalized) ? normalized : null;
}
