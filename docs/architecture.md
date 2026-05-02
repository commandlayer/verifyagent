# VerifyAgent Architecture

VerifyAgent.eth is the public verifier for CommandLayer receipts.

## Responsibilities

- **VerifyAgent** verifies receipts.
- **SDK (`@commandlayer/agent-sdk`)** creates signed receipts.
- **ENS** resolves signer keys (such as `cl.sig.pub`) for signer identity.

## Role boundaries

- VerifyAgent answers: "Is this receipt valid?"
- SDK answers: "How do developers create receipts?"

## Repository scope

This repository focuses on verification UX and core verification logic.
If receipt fields are changed after signing, verification returns **INVALID**.


## Canonical values

- signer: `runtime.commandlayer.eth`
- key id: `vC4WbcNoq2znSCiQ`
- canonicalization: `json.sorted_keys.v1`
- signature algorithm: `ed25519`
