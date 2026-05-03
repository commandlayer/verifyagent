# VerifyAgent Architecture

VerifyAgent.eth is the public verifier for receipts produced by ENS-named agents.

## Responsibilities

- **VerifyAgent** verifies receipts.
- **SDK (`@commandlayer/agent-sdk`)** creates signed receipts.
- **ENS** resolves signer identity and verification metadata from ENS TXT records (including `cl.sig.pub`, `cl.sig.kid`, `cl.sig.canonical`, and `cl.receipt.signer`).

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
