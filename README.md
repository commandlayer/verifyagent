# VerifyAgent

VerifyAgent.eth is the public verifier for CommandLayer receipts.

VerifyAgent is the reference verifier: paste or submit a receipt, resolve signer metadata, recompute the canonical hash, verify Ed25519 signatures, and return a clear **VERIFIED** or **INVALID** result.

## Links

- Live verifier UI: https://www.commandlayer.org/verify.html
- API verifier endpoint: https://www.commandlayer.org/api/verify
- Callable VerifyAgent endpoint: https://www.commandlayer.org/api/agents/verifyagent
- SDK repo: https://github.com/commandlayer/agent-sdk

## Install the SDK

```bash
npm install @commandlayer/agent-sdk
```

## Canonical flow

- `@commandlayer/agent-sdk` creates a signed receipt.
- VerifyAgent verifies the signed receipt.
- A tampered signed receipt returns **INVALID**.

## Verification flow

1. Agent executes an action.
2. `@commandlayer/agent-sdk` emits a signed receipt.
3. VerifyAgent resolves signer metadata (`cl.sig.pub`, `cl.sig.kid`, `cl.sig.canonical`, `cl.receipt.signer`).
4. VerifyAgent canonicalizes + hashes payload, then verifies Ed25519 signature.
5. Result is **VERIFIED** or **INVALID** with explicit checks.

## Scope

VerifyAgent is a verification surface and reference verifier implementation.
It does not create receipts.

## Run locally

```bash
npm install
npm run dev
```

Open: `http://localhost:4173/verify.html`

## Sample and tamper checks

- **Load Sample** verifies a real signed receipt.
- **Load Tampered** changes output while keeping original hash/signature to demonstrate tamper detection.
- `examples/sample-receipt.json` verifies as **VERIFIED**.
- `examples/tampered-receipt.json` verifies as **INVALID**.

## Canonical values

- signer: `runtime.commandlayer.eth`
- key id: `vC4WbcNoq2znSCiQ`
- canonicalization: `json.sorted_keys.v1`
- signature algorithm: `ed25519`

## ENS signer records

Known signer records for `runtime.commandlayer.eth`:

- `cl.receipt.signer = runtime.commandlayer.eth`
- `cl.sig.kid = vC4WbcNoq2znSCiQ`
- `cl.sig.pub = ed25519:A5Q4Ff6BA8y/U0BxJcj8utWm8UemKGHRMCPQyoKRZQs=`
- `cl.sig.canonical = json.sorted_keys.v1`

When live ENS text resolution is unavailable in-browser, VerifyAgent uses a clearly labeled resolver fallback for `runtime.commandlayer.eth` only.
