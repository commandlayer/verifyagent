# VerifyAgent

VerifyAgent is a public verifier for CommandLayer receipts. It lets anyone paste a receipt, resolve signer metadata, recompute the canonical hash, verify Ed25519 signatures, and see a clear **VERIFIED** or **INVALID** result.

## Live verifier

https://www.commandlayer.org/verify.html

## Developer wrapper demo

examples/wrapped-agent-demo

## Core flow

Agent action → signed receipt → ENS-resolved signer key → VerifyAgent → **VERIFIED** / **INVALID**

## What VerifyAgent is

- A public verification surface for signed agent receipts.
- A hackathon-friendly demo for end-to-end proof flows.
- A reference implementation for ENS signer metadata + receipt verification.

## What VerifyAgent is not

- Not commercial x402/payment gateway code.
- Not dashboard/auth/org-account infrastructure.
- Not a hosted backend dependency for verification.
- Not an npm package release (this repo does not claim a published package yet).

## Flow: Agent → Receipt → VerifyAgent → Proof

1. Agent runs an action.
2. Wrapper emits a signed receipt.
3. VerifyAgent resolves signer metadata (`cl.sig.pub`, `cl.sig.kid`, `cl.sig.canonical`, `cl.receipt.signer`).
4. VerifyAgent canonicalizes + hashes payload, then verifies Ed25519 signature.
5. Output is **VERIFIED** or **INVALID** with explicit check fields.

## Run the verifier

```bash
npm install
npm run dev
```

Open: `http://localhost:4173/verify.html`

## Run the wrapped agent demo

```bash
cd examples/wrapped-agent-demo
npm install
npm run demo
```

Developers can use this wrapped-agent demo as the starting point for adding signed receipts to their own agents.

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

## ENS signer resolution

VerifyAgent treats ENS as the signer key registry for CommandLayer receipts. A receipt declares a signer such as `runtime.commandlayer.eth`. During verification, the verifier resolves that signer’s TXT records, including `cl.sig.pub` and `cl.sig.kid`, and uses the resolved public key to validate the Ed25519 signature.

The browser demo includes a clearly labeled fallback resolver only for the known demo signer `runtime.commandlayer.eth` when live ENS text resolution is unavailable in-browser. This fallback is for demo reliability and does not allow unknown signers to verify.

In production-style verification, signer keys should be resolved from ENS during the verification step. The receipt remains portable: any verifier can recompute the hash and validate the signature against the signer key published under ENS.

### What is verified

- canonical payload matches `metadata.proof.hash_sha256`
- Ed25519 signature validates against resolved signer key
- signer/key id matches expected ENS records when present
- tampered input/output fails verification

### What fallback does not mean

- fallback does not make arbitrary signers valid
- fallback does not bypass hash checks
- fallback does not bypass signature checks
