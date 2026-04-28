# VerifyAgent Architecture

VerifyAgent is the public verifier layer for CommandLayer receipts.

## Responsibilities

- **VerifyAgent** verifies receipts.
- **SDK** creates and wraps receipts.
- **Runtime** emits receipts during action execution.
- **ENS** resolves signer keys (such as `cl.sig.pub`) for signer identity.
- **Commercial services** handle hosted/high-volume verification workflows.
- **Agent Cards** describe agent identity and capabilities.

## Role boundaries (exact distinction)

“VerifyAgent answers: Is this receipt valid?”
“Runtime answers: What action ran?”
“SDK answers: How do developers create receipts?”
“Agent Cards answer: What is this agent?”
“Commercial answers: How do teams verify at scale?”

## Public Commons/MIT scope for this repo

This repository focuses on local/public verification UX and core verification logic.
It intentionally excludes:

- x402 implementation
- hosted dashboard/auth/org-account features
- paywalled/commercial API code
