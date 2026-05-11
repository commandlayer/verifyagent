# Wrap Your Agent

## VerifyAgent positioning

VerifyAgent.eth is the public verifier for receipts produced by ENS-named agents.

- Live verifier UI: https://www.commandlayer.org/verify.html
- API verifier: https://www.commandlayer.org/api/verify
- Callable VerifyAgent: https://www.commandlayer.org/api/agents/verifyagent

## Install the SDK

```bash
npm install @commandlayer/agent-sdk
```

- SDK npm: https://www.npmjs.com/package/@commandlayer/agent-sdk
- SDK GitHub: https://github.com/commandlayer/agent-sdk

## Division of responsibility

- `@commandlayer/agent-sdk` creates signed receipts.
- VerifyAgent verifies signed receipts.

If `input`, `output`, or any signed field is tampered after signing, VerifyAgent returns **INVALID**.

## Canonical flow

- `@commandlayer/agent-sdk` creates a signed receipt.
- VerifyAgent verifies the signed receipt.
- A tampered signed receipt returns **INVALID**.

## Canonical values

- signer: `runtime.commandlayer.eth`
- key id: `vC4WbcNoq2znSCiQ`
- canonicalization: `json.sorted_keys.v1`
- signature algorithm: `ed25519`

## Quickstart

```js
import { CommandLayer } from "@commandlayer/agent-sdk";

const cl = new CommandLayer({
  agent: "runtime.commandlayer.eth",
  privateKey: process.env.CL_PRIVATE_KEY_PEM,
  keyId: "vC4WbcNoq2znSCiQ",
  verifierUrl: "https://www.commandlayer.org/api/verify"
});

const result = await cl.wrap("summarize", async () => {
  return { summary: "hello world" };
});

console.log(result.output);
console.log(result.receipt);

const verified = await cl.verify(result.receipt);
console.log(verified.status); // "VERIFIED" or "INVALID"
```

## What `wrap()` returns

- `output`: action result from your wrapped function
- `receipt`: signed CommandLayer receipt

The signed receipt includes fields like `signer`, `verb`, `input`, `output`, `execution`, `ts`, `metadata.proof.hash_sha256`, and `signature`.

## CLAS Trust Verification v1

CLAS Trust Verification v1 is an extended receipt shape that adds a `trust_verb` and family/version markers. VerifyAgent detects CLAS v1 automatically and applies stricter schema validation in addition to hash and signature checks.

A CLAS v1 receipt includes:

```json
{
  "version": "clas_trust_verification.v1",
  "family": "clas_trust_verification",
  "metadata": {
    "proof": {
      "trust_verb": "verify",
      "canonicalization": "json.sorted_keys.v1",
      "hash_sha256": "<hex>"
    }
  }
}
```

Recognized trust verbs: `verify`, `authenticate`, `authorize`, `attest`, `sign`, `permit`, `grant`, `approve`, `reject`, `endorse`.

CLAS v1 validity requires `schema_valid && hash_matched && signature_valid`. Legacy receipts require only `hash_matched && signature_valid`.

## Verify response

```json
{
  "valid": true,
  "status": "VERIFIED",
  "signerEns": "runtime.commandlayer.eth",
  "keyId": "vC4WbcNoq2znSCiQ",
  "publicKeySource": "live ENS text record",
  "canonicalization": "json.sorted_keys.v1",
  "checks": {
    "schema_valid": true,
    "hash_matched": true,
    "signature_valid": true,
    "signer_resolved": true,
    "signer_matched": true,
    "trust_verb_identified": true,
    "trust_verb": "verify"
  },
  "debug": {
    "recomputed_hash_sha256": "<hex>",
    "expected_hash_sha256": "<hex>",
    "key_id_matched": true
  }
}
```
