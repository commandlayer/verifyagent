# VerifyAgent

VerifyAgent is a public verifier for CommandLayer receipts. It lets anyone paste a receipt, resolve signer metadata, recompute the canonical hash, verify Ed25519 signatures, and see a clear **VERIFIED** or **INVALID** result.

## What VerifyAgent is

- A public verification surface for signed agent receipts.
- A hackathon-friendly demo for end-to-end proof flows.
- A reference implementation for ENS signer metadata + receipt verification.

## What VerifyAgent is not

- Not commercial x402/payment gateway code.
- Not dashboard/auth/org-account infrastructure.
- Not a hosted backend dependency for verification.

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

This writes `examples/wrapped-agent-demo/out/receipt.json` and prints the verify URL.

## Sample receipt status

- `examples/sample-receipt.json` is a **fixture/demo sample** and is clearly labeled `fixture_only`.
- It is **not** signed by the current `runtime.commandlayer.eth` fallback private key (`cl.sig.pub = ed25519:hhyCuPNoMk4JtEvGEV8F6nMZ4uDO1EcyizPufmnJTOY=`), so verification returns **INVALID**.
- Use `examples/wrapped-agent-demo` to generate a real signed receipt that verifies with `verifyReceipt` when you provide the matching signer key material.

## ENS signer records

Known signer records for `runtime.commandlayer.eth`:

- `cl.receipt.signer = runtime.commandlayer.eth`
- `cl.sig.kid = vC4WbcNoq2znSCiQ`
- `cl.sig.pub = ed25519:hhyCuPNoMk4JtEvGEV8F6nMZ4uDO1EcyizPufmnJTOY=`
- `cl.sig.canonical = json.sorted_keys.v1`

When live ENS text resolution is unavailable in-browser, VerifyAgent uses a clearly labeled resolver fallback for `runtime.commandlayer.eth` only.
