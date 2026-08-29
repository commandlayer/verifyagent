import * as installedRuntimeCore from '@commandlayer/runtime-core';
import { resolveSignerFromEns } from './ens.js';

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
  const ens = await resolveSignerFromEns(signerId, options.ens || {});
  const resolveKey = async ({ kid, signerId: requestedSigner }) => {
    if (!ens.ensResolved) return null;
    if (requestedSigner !== signerId) return null;
    const pub = ens.records?.['cl.sig.pub'];
    if (!pub || typeof runtimeCore.parsePublicKey !== 'function') return null;
    return {
      rawPublicKey: runtimeCore.parsePublicKey(pub),
      kid: ens.records?.['cl.sig.kid'] || kid,
      signerId: ens.records?.['cl.receipt.signer'] || requestedSigner,
    };
  };

  let verified;
  try {
    verified = await runtimeCore.verifyFactoryExecutionReceipt(receipt, {
      expectedSigner: signerId,
      expectedKid: receipt.proof.kid,
      resolveKey,
    });
  } catch (error) {
    return invalid(error instanceof Error ? error.message : String(error), receipt);
  }

  const valid = verified?.valid === true;
  return {
    valid,
    ok: valid,
    status: valid ? 'VERIFIED' : (ens.ensResolved ? 'INVALID' : 'INDETERMINATE'),
    signerEns: ens.records?.['cl.receipt.signer'] || signerId || 'unknown',
    keyId: receipt.proof.kid || null,
    publicKeySource: ens.ensResolved ? (ens.keySource || 'ENS text record') : 'not resolved',
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
    errors: valid ? [] : [verified?.reason || (ens.ensResolved ? 'ERR_FACTORY_EXECUTION_RECEIPT_INVALID' : 'ERR_ENS_RESOLUTION_FAILED')],
  };
}
