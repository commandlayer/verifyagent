import { createHash } from 'node:crypto';
import { resolveSignerFromEns } from './ens.js';
import {
  detectReceiptMode,
  normalizeTrustVerb,
  validateClasTrustV1Shape,
  validateClasExecutionReceiptShape,
  getClasExecutionReceiptSchemaErrors,
  validateLegacyReceiptShape
} from './schema.js';
import * as runtimeCore from '@commandlayer/runtime-core';

const ED25519_SPKI_PREFIX_HEX = '302a300506032b6570032100';

const EXECUTION_FIELDS = ['receipt_id', 'verb', 'agent', 'action'];
const SETTLEMENT_FIELDS = ['receipt_id', 'settlement'];
const RAW_TX_HASH_RE = /^0x[a-fA-F0-9]{64}$/;

function fieldsEqual(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length && actual.every((field, index) => field === expected[index]);
}

function scopedPayload(receipt, fields) {
  return Object.fromEntries(fields.map((field) => [field, receipt?.[field]]));
}

function findScopedProof(receipt, type) {
  return Array.isArray(receipt?.proofs) ? receipt.proofs.find((proof) => proof?.type === type) : null;
}

function proofResult(type, proof, expectedFields) {
  return {
    type,
    signer: proof?.signer || 'unknown',
    covered_fields: Array.isArray(proof?.covers) ? proof.covers : [],
    signature_valid: false,
    status: proof ? 'invalid' : 'missing',
    errors: proof ? [] : ['ERR_MISSING_PROOF'],
    expected_fields: expectedFields
  };
}

async function verifyScopedProof(receipt, proof, expectedFields, options = {}) {
  const result = proofResult(proof?.type || 'unknown', proof, expectedFields);
  if (!proof) return result;

  if (!fieldsEqual(proof.covers, expectedFields)) result.errors.push('ERR_UNEXPECTED_COVERS');
  if (proof.canonicalization !== runtimeCore.CANONICAL_METHOD) result.errors.push('ERR_UNSUPPORTED_CANONICALIZATION');
  if (proof.signature?.alg !== runtimeCore.SIGNATURE_ALG) result.errors.push('ERR_UNSUPPORTED_SIGNATURE_ALG');
  if (typeof proof.signature?.kid !== 'string' || proof.signature.kid.length === 0) result.errors.push('ERR_MISSING_SIGNATURE_KID');
  if (typeof proof.signature?.value !== 'string' || proof.signature.value.length === 0) result.errors.push('ERR_MISSING_SIGNATURE_VALUE');
  if (typeof proof.signer !== 'string' || proof.signer.length === 0) result.errors.push('ERR_MISSING_SIGNER');

  if (proof.type === 'execution' && receipt?.agent?.ens && proof.signer !== receipt.agent.ens) {
    result.errors.push('ERR_AGENT_ENS_SIGNER_MISMATCH');
  }

  const ens = await resolveSignerFromEns(proof.signer, options.ens || {});
  result.signer = ens.records?.['cl.receipt.signer'] || proof.signer || 'unknown';
  if (!ens.ensResolved) result.errors.push('ERR_ENS_RESOLUTION_FAILED');
  if (ens.ensResolved && proof.signature?.kid !== ens.records['cl.sig.kid']) result.errors.push('ERR_ENS_KID_MISMATCH');
  if (ens.ensResolved && proof.canonicalization !== (ens.records['cl.sig.canonical'] || runtimeCore.CANONICAL_METHOD)) result.errors.push('ERR_ENS_CANONICAL_MISMATCH');
  if (ens.ensResolved && proof.signer !== ens.records['cl.receipt.signer']) result.errors.push('ERR_ENS_SIGNER_MISMATCH');

  try {
    const canonical = runtimeCore.canonicalize(scopedPayload(receipt, expectedFields));
    if (ens.ensResolved) {
      const publicKeyPem = ensurePemFromEnsPub(ens.records['cl.sig.pub']);
      result.signature_valid = runtimeCore.verifyCanonical(canonical, proof.signature?.value || '', publicKeyPem);
      if (!result.signature_valid) result.errors.push('ERR_SIGNATURE_INVALID');
    }
  } catch (error) {
    result.errors.push(mapRuntimeCoreError(error));
  }

  result.status = result.errors.length === 0 && result.signature_valid ? 'valid' : 'invalid';
  return result;
}

function evaluateSettlementPrivacy(receipt) {
  const settlement = receipt?.settlement;
  if (!settlement) return { present: false, status: 'missing', display: null, errors: [] };
  const errors = [];
  const display = {
    verification_mode: settlement.verification?.mode || null,
    viewer_required: Boolean(settlement.verification?.viewer_required)
  };
  if (settlement.privacy === 'stealth_address') {
    display.message = 'Private settlement committed';
    display.payee_commitment = settlement.payee_commitment || null;
    if (typeof settlement.stealth_address === 'string' && settlement.stealth_address.length > 0) errors.push('ERR_STEALTH_ADDRESS_DISCLOSED');
    if (typeof settlement.payment_ref === 'string') {
      if (RAW_TX_HASH_RE.test(settlement.payment_ref)) errors.push('ERR_RAW_PAYMENT_REF_DISCLOSED');
      else display.payment_ref = settlement.payment_ref;
    }
  }
  return { present: true, status: errors.length === 0 ? 'valid' : 'invalid', display, errors };
}

async function verifyScopedExecutionReceipt(receipt, options = {}) {
  const schemaValid = validateClasExecutionReceiptShape(receipt);
  const schemaErrors = schemaValid
    ? []
    : getClasExecutionReceiptSchemaErrors().map((error) => `ERR_SCHEMA:${error.instancePath || '/'}:${error.keyword}`);

  const executionProof = await verifyScopedProof(receipt, findScopedProof(receipt, 'execution'), EXECUTION_FIELDS, options);
  const settlementPresent = Boolean(receipt?.settlement);
  const settlementProof = settlementPresent
    ? await verifyScopedProof(receipt, findScopedProof(receipt, 'settlement'), SETTLEMENT_FIELDS, options)
    : proofResult('settlement', null, SETTLEMENT_FIELDS);
  const privacy = evaluateSettlementPrivacy(receipt);
  const valid = schemaValid
    && executionProof.status === 'valid'
    && (!settlementPresent || (settlementProof.status === 'valid' && privacy.status === 'valid'));

  return {
    valid,
    ok: valid,
    status: valid ? 'VERIFIED' : 'INVALID',
    signerEns: executionProof.signer,
    keyId: findScopedProof(receipt, 'execution')?.signature?.kid || null,
    publicKeySource: 'scoped proof ENS text record',
    canonicalization: findScopedProof(receipt, 'execution')?.canonicalization || null,
    checks: {
      schema: schemaValid,
      canonical_hash: null,
      canonical_payload: executionProof.status !== 'missing',
      signature: executionProof.signature_valid,
      signer: executionProof.status !== 'missing' && !executionProof.errors.includes('ERR_MISSING_SIGNER'),
      scoped_execution_receipt: true
    },
    proofCards: { execution: executionProof, settlement: settlementProof },
    settlementPrivacy: privacy,
    copy: ['Private settlement, public accountability.', 'Execution and settlement are independently attested.'],
    errors: [...schemaErrors, ...executionProof.errors, ...(settlementPresent ? settlementProof.errors : []), ...privacy.errors]
  };
}

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

function ensurePemFromEnsPub(ensPubValue) {
  const rawPublicKey = runtimeCore.parsePublicKey(ensPubValue);
  const der = Buffer.concat([Buffer.from(ED25519_SPKI_PREFIX_HEX, 'hex'), Buffer.from(rawPublicKey)]);
  const body = der.toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`;
}

export async function verifyReceipt(receiptInput, options = {}) {
  let receipt;
  try { receipt = typeof receiptInput === 'string' ? JSON.parse(receiptInput) : receiptInput; } catch { return invalidResult(); }

  const mode = detectReceiptMode(receipt);
  if (mode === 'clas_execution_v1') return verifyScopedExecutionReceipt(receipt, options);

  const schemaValid = mode === 'clas_v1' ? validateClasTrustV1Shape(receipt) : validateLegacyReceiptShape(receipt);
  const ens = await resolveSignerFromEns(receipt?.signer, options.ens || {});
  if (!ens.ensResolved) return invalidResult({ checks: { schema: schemaValid, canonical_hash: false, signature: false, signer: false }, error: 'ENS resolution failed — cannot verify without public key' });

  let runtime;
  try {
    const publicKeyPem = ensurePemFromEnsPub(ens.records?.['cl.sig.pub']);
    const runtimeReceipt = { ...receipt };
    if (!Object.prototype.hasOwnProperty.call(runtimeReceipt, 'agent')) {
      Object.defineProperty(runtimeReceipt, 'agent', {
        value: receipt?.signer,
        enumerable: false,
        configurable: true,
        writable: false
      });
    }

    runtime = runtimeCore.verifyCommandLayerReceipt(runtimeReceipt, {
      publicKeyPemOrDer: publicKeyPem,
      ensRecord: {
        signer: ens.records['cl.receipt.signer'] || ens.signer,
        kid: ens.records['cl.sig.kid'],
        canonical: ens.records['cl.sig.canonical'] || 'json.sorted_keys.v1'
      }
    });
  } catch (error) {
    const ensSigner = ens.records['cl.receipt.signer'] || ens.signer || null;
    runtime = {
      ok: false,
      status: 'INVALID',
      checks: {
        schema: false,
        canonical_hash: false,
        signature: false,
        signer: Boolean(ensSigner) && receipt?.signer === ensSigner
      },
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
  const canonical = runtimeCore.buildCanonicalProof(receipt);
  if (typeof runtimeCore.sha256HexUtf8 === 'function') {
    return runtimeCore.sha256HexUtf8(canonical);
  }

  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}
