# VerifyAgent

VerifyAgent is a public verifier for CommandLayer receipts. It lets anyone paste a receipt, resolve signer metadata, recompute the canonical hash, verify Ed25519 signatures, and see a clear **VERIFIED** or **INVALID** result.

## Live verifier

https://www.commandlayer.org/verify.html

## Developer wrapper demo (reference)

examples/wrapped-agent-demo

## Install the SDK

```bash
npm install @commandlayer/agent-sdk
```

## Core flow

Agent action → `@commandlayer/agent-sdk` creates signed receipt → VerifyAgent verifies receipt → **VERIFIED** / **INVALID**

If a receipt is tampered after signing (for example, changing `input` or `output`), VerifyAgent returns **INVALID**.

## What VerifyAgent is

- A public verification surface for signed CommandLayer receipts.
- A reference implementation for ENS signer metadata + receipt verification.

## What VerifyAgent is not

- Not agent runtime orchestration.
- Not signer key custody.
- Not a hosted backend dependency for verification.

## Flow: Agent → Receipt → VerifyAgent → Proof

1. Agent runs an action.
2. `@commandlayer/agent-sdk` emits a signed receipt.
3. VerifyAgent resolves signer metadata (`cl.sig.pub`, `cl.sig.kid`, `cl.sig.canonical`, `cl.receipt.signer`).
4. VerifyAgent canonicalizes + hashes payload, then verifies Ed25519 signature.
5. Output is **VERIFIED** or **INVALID** with explicit check fields.

## Run the verifier

```bash
npm install
npm run dev
```

Open: `http://localhost:4173/verify.html`

## Run the wrapped agent demo (reference)

```bash
cd examples/wrapped-agent-demo
npm install
npm run demo
```

This writes `examples/wrapped-agent-demo/out/receipt.json` and prints the verify URL.

## Sample & tamper checks

- **Load Sample** verifies a real signed receipt.
- **Load Tampered** changes the output while keeping the original hash/signature, proving tamper detection.
- `examples/sample-receipt.json` is a public sample that verifies as **VERIFIED**.
- `examples/tampered-receipt.json` is derived from the sample, with one signed field changed while hash/signature are unchanged, and verifies as **INVALID**.

## ENS signer records

Known signer records for `runtime.commandlayer.eth`:

- `cl.receipt.signer = runtime.commandlayer.eth`
- `cl.sig.kid = vC4WbcNoq2znSCiQ`
- `cl.sig.pub = ed25519:A5Q4Ff6BA8y/U0BxJcj8utWm8UemKGHRMCPQyoKRZQs=`
- `cl.sig.canonical = json.sorted_keys.v1`

When live ENS text resolution is unavailable in-browser, VerifyAgent uses a clearly labeled resolver fallback for `runtime.commandlayer.eth` only.
