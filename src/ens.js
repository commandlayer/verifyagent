// ENS resolution for CommandLayer receipt verification.
// IMPORTANT: there are no hardcoded fallback keys. If ENS resolution fails
// (no resolver, no live RPC, or missing TXT records), verification must fail.
// Do not add fallback keys — they bypass live key rotation and create exploit surface.

async function defaultEnsTextResolver() {
  return null;
}

export async function resolveSignerFromEns(signerEnsName, options = {}) {
  const resolver = options.textResolver || defaultEnsTextResolver;
  const requiredKeys = ['cl.sig.pub', 'cl.sig.kid', 'cl.sig.canonical', 'cl.receipt.signer'];
  const records = {};

  let liveOk = true;
  for (const key of requiredKeys) {
    try {
      const value = await resolver(signerEnsName, key);
      if (!value) {
        liveOk = false;
        break;
      }
      records[key] = value;
    } catch {
      liveOk = false;
      break;
    }
  }

  if (liveOk) {
    return {
      signer: signerEnsName,
      records,
      ensResolved: true,
      keySource: 'live ENS text record'
    };
  }

  return {
    signer: signerEnsName || 'unknown',
    records: {},
    ensResolved: false,
    keySource: 'not resolved'
  };
}
