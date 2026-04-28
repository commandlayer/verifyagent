/**
 * ENS resolution helper.
 *
 * TODO: Wire this to a real ENS provider (ethers + RPC) and read text record
 * cl.sig.pub from the signer ENS name.
 */
export async function resolveSignerFromEns(signerEnsName) {
  return {
    live: false,
    ensResolved: false,
    signer: signerEnsName || 'unknown',
    keySource: 'ENS resolution not yet live in local demo',
    pubkey: null
  };
}
