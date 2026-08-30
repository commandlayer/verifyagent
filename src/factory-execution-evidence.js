import * as installedRuntimeCore from '@commandlayer/runtime-core';
import { resolveSignerFromEns } from './ens.js';
import { resolveFactoryKeyFromDocument } from './factory-key-document.js';

export const FACTORY_EXECUTION_RECEIPT_PROFILE = 'commandlayer.execution-evidence.v1';

function coreFrom(options = {}) {
  return options.runtimeCore || installedRuntimeCore;
}

function invalid(reason, receipt = null) {
  return {
    valid: false,
    ok: false,
    status: 'INVALID',
    signerEns: receipt?.proof?.signer_id || 'unknown',
    keyId: receipt?.proof?.kid || null,
    publicKeySource: 'not resolved',
    canonicalization: receipt?.proof?.canonical || null,
    truth_certified: false,
    proof_scope: 'execution_integrity_and_provenance',
    checks: {
      schema: false,
      signature: false,
      signer: false,
      service_binding: false,
      workflow_binding: false,
      payment_separated: false,
    },
    errors: [reason],
  };
}

export function isFactoryExecutionEvidenceReceipt(receipt) {
  return Boolean(
    receipt
    && typeof receipt === 'object'
    && receipt.profile === FACTORY_EXECUTION_RECEIPT_PROFILE
    && receipt.execution
    && receipt.proof
  );
}

export async function verifyFactoryExecutionEvidenceReceipt(receipt, options = {}) {
  if (!isFactoryExecutionEvidenceReceipt(receipt)) {
    return invalid('ERR_FACTORY_EXECUTION_RECEIPT_SHAPE', receipt);
  }

  const runtimeCore = coreFrom(options);
  if (typeof runtimeCore.verifyFactoryExecutionReceipt !== 'function') {
    return {
      ...invalid('ERR_RUNTIME_CORE_FACTORY_SURFACE_UNAVAILABLE', receipt),
      status: 'INDETERMINATE',
    };
  }

  const signerId = receipt.proof.signer_id;
  const kid = receipt.proof.kid;
  const keyDocument = await resolveFactoryKeyFromDocument(
    { kid, signerId },
    options.keyDocument || {},
  );

  let resolvedKey = keyDocument.state === 'resolved' ? keyDocument.key : null;
  let publicKeySource = keyDocument.state === 'resolved' ? keyDocument.source : 'not resolved';
  let ens = null;

  // A configured HTTPS trust root is authoritative when it responds with a
  // document-level/key-level failure. Do not bypass a key conflict by silently
  // switching identity systems. ENS is only an availability fallback when the
  // HTTPS trust root is disabled or genuinely unavailable.
  if (!resolvedKey && (keyDocument.state === 'disabled' || keyDocument.state === 'unavailable')) {
    ens = await resolveSignerFromEns(signerId, options.ens || {});
    if (ens.ensResolved) publicKeySource = ens.keySource || 'ENS text record';
  }

  const resolveKey = async ({ kid: requestedKid, signerId: requestedSigner }) => {
    if (requestedSigner !== signerId || requestedKid !== kid) return null;
    if (resolvedKey) return resolvedKey;
    if (!ens?.ensResolved) return null;
    const pub = ens.records?.['cl.sig.pub'];
    if (!pub || typeof runtimeCore.parsePublicKey !== 'function') return null;
    return {
      rawPublicKey: runtimeCore.parsePublicKey(pub),
      kid: ens.records?.['cl.sig.kid'] || requestedKid,
      signerId: ens.records?.['cl.receipt.signer'] || requestedSigner,
    };
  };

  let verified;
  try {
    verified = await runtimeCore.verifyFactoryExecutionReceipt(receipt, {
      expectedSigner: signerId,
      expectedKid: kid,
      resolveKey,
    });
  } catch (error) {
    return invalid(error instanceof Error ? error.message : String(error), receipt);
  }

  const valid = verified?.valid === true;
  const verificationKeyResolved = Boolean(resolvedKey || ens?.ensResolved);
  const resolutionError = keyDocument.state === 'authoritative_failure'
    ? keyDocument.reason
    : (!verificationKeyResolved && keyDocument.state === 'unavailable'
      ? keyDocument.reason
      : null);

  return {
    valid,
    ok: valid,
    status: valid ? 'VERIFIED' : (verificationKeyResolved ? 'INVALID' : 'INDETERMINATE'),
    signerEns: ens?.records?.['cl.receipt.signer'] || signerId || 'unknown',
    keyId: kid || null,
    publicKeySource,
    canonicalization: receipt.proof.canonical || null,
    truth_certified: false,
    proof_scope: 'execution_integrity_and_provenance',
    checks: {
      schema: verified?.checks?.structureValid === true && verified?.checks?.profileValid === true,
      signature: verified?.checks?.signatureValid === true,
      signer: verified?.checks?.signerMatched === true && verified?.checks?.kidMatched === true,
      service_binding: verified?.checks?.serviceBindingValid === true,
      workflow_binding: Boolean(receipt.execution.workflow_hash) && verified?.checks?.signatureValid === true,
      payment_separated: verified?.checks?.paymentFieldsAbsent === true,
    },
    runtime_checks: verified?.checks || null,
    errors: valid ? [] : [
      resolutionError
      || verified?.reason
      || (verificationKeyResolved ? 'ERR_FACTORY_EXECUTION_RECEIPT_INVALID' : 'ERR_FACTORY_KEY_RESOLUTION_FAILED'),
    ],
  };
}
