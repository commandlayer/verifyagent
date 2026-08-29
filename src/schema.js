import Ajv from 'ajv';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { clasSchemaMap, TRUST_VERBS, CLAS_EXECUTION_RECEIPT_SCHEMA } from './generated/clas-schema-map.js';

const TRUST_VERB_SET = new Set(TRUST_VERBS);

const clasValidators = Object.fromEntries(
  Object.entries(clasSchemaMap).map(([verb, entry]) => {
    const ajv = new Ajv({ allErrors: true, strict: false });
    addFormats(ajv);
    return [verb, ajv.compile(entry.receipt)];
  })
);

const executionAjv = new Ajv2020({ allErrors: true, strict: false });
addFormats(executionAjv);
const executionReceiptValidator = executionAjv.compile(CLAS_EXECUTION_RECEIPT_SCHEMA);

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function hasString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

function isValidLegacySignature(signature) {
  return isObject(signature)
    && signature.alg === 'Ed25519'
    && hasString(signature.kid)
    && hasString(signature.value);
}

function isValidMultiSignature(signatures) {
  if (!Array.isArray(signatures) || signatures.length === 0) return false;
  const roles = new Set(['user', 'solver', 'relayer', 'agent', 'runtime', 'verifier']);
  return signatures.every((signature) => isObject(signature)
    && signature.alg === 'Ed25519'
    && hasString(signature.kid)
    && hasString(signature.value)
    && roles.has(signature.role));
}

function isValidProofSignature(signature) {
  return isValidLegacySignature(signature) || isValidMultiSignature(signature);
}

export function detectReceiptMode(receipt) {
  if (!isObject(receipt)) return 'legacy';
  if (receipt?.schema === 'clas.execution.receipt.v1') return 'clas_execution_v1';

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
  const proof = receipt?.metadata?.proof;
  return hasString(receipt.signer)
    && isObject(receipt.metadata)
    && isObject(proof)
    && hasString(proof.canonicalization)
    && isObject(proof.hash)
    && proof.hash.alg === 'SHA-256'
    && hasString(proof.hash.value)
    && isValidProofSignature(proof.signature);
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

export function validateClasExecutionReceiptShape(receipt) {
  return executionReceiptValidator(receipt) === true;
}

export function getClasExecutionReceiptSchemaErrors() {
  return executionReceiptValidator.errors ? structuredClone(executionReceiptValidator.errors) : [];
}

export function normalizeTrustVerb(verb) {
  if (typeof verb !== 'string') return null;
  const normalized = verb.trim().toLowerCase();
  return TRUST_VERB_SET.has(normalized) ? normalized : null;
}
