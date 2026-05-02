# VerifyAgent Architecture

VerifyAgent is the public verifier layer for CommandLayer receipts.

## Responsibilities

- **VerifyAgent** verifies receipts.
- **SDK (`@commandlayer/agent-sdk`)** creates and wraps signed receipts.
- **Runtime** emits receipts during action execution.
- **ENS** resolves signer keys (such as `cl.sig.pub`) for signer identity.
- **Agent Cards** describe agent identity and capabilities.

## Role boundaries (exact distinction)

“VerifyAgent answers: Is this receipt valid?”
“Runtime answers: What action ran?”
“SDK answers: How do developers create receipts?”
“Agent Cards answer: What is this agent?”

## Repository scope

This repository focuses on local/public verification UX and core verification logic.
It does not include runtime orchestration or signer key custody.
