const FALLBACK_SIGNER = 'runtime.commandlayer.eth';
const FALLBACK_RECORDS = {
  'cl.receipt.signer': 'runtime.commandlayer.eth',
  'cl.sig.kid': 'vC4WbcNoq2znSCiQ',
  'cl.sig.pub': 'ed25519:A5Q4Ff6BA8y/U0BxJcj8utWm8UemKGHRMCPQyoKRZQs=',
  'cl.sig.canonical': 'json.sorted_keys.v1'
};

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

  if (signerEnsName === FALLBACK_SIGNER) {
    return {
      signer: signerEnsName,
      records: { ...FALLBACK_RECORDS },
      ensResolved: true,
      keySource: 'local demo fallback (runtime.commandlayer.eth only)'
    };
  }

  return {
    signer: signerEnsName || 'unknown',
    records: {},
    ensResolved: false,
    keySource: 'not resolved'
  };
}
