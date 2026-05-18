import Ajv from 'ajv';
import { clasSchemaMap, TRUST_VERBS } from './generated/clas-schema-map.js';

const TRUST_VERB_SET = new Set(TRUST_VERBS);

const clasValidators = Object.fromEntries(
  Object.entries(clasSchemaMap).map(([verb, entry]) => {
    const ajv = new Ajv({ allErrors: true, strict: false });
    return [verb, ajv.compile(entry.receipt)];
  })
);

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function hasString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

export function detectReceiptMode(receipt) {
  if (!isObject(receipt)) return 'legacy';
  const proof = receipt.metadata?.proof;
  const metadata = receipt.metadata;

  const clasIndicators = [
    receipt?.version === '1.0.0',
    receipt?.family === 'trust-verification',
    receipt?.version === 'clas_trust_verification.v1',
    receipt?.version === 'v1',
    receipt?.family === 'clas_trust_verification',
    metadata?.family === 'trust-verification',
    metadata?.version === '1.0.0',
    metadata?.family === 'clas_trust_verification',
    metadata?.version === 'clas_trust_verification.v1',
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

  const version = receipt?.version ?? receipt?.metadata?.version;
  const family = receipt?.family ?? receipt?.metadata?.family;
  if (!['1.0.0', 'clas_trust_verification.v1', 'v1'].includes(version)) return false;
  if (!['trust-verification', 'clas_trust_verification'].includes(family)) return false;

  const verb = normalizeTrustVerb(receipt?.verb);
  if (!verb || !TRUST_VERB_SET.has(verb)) return false;

  const validator = clasValidators[verb];
  if (!validator) return false;
  return validator(receipt) === true;
}

export function normalizeTrustVerb(verb) {
  if (typeof verb !== 'string') return null;
  const normalized = verb.trim().toLowerCase();
  return TRUST_VERB_SET.has(normalized) ? normalized : null;
}
