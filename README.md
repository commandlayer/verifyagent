# VerifyAgent.eth

VerifyAgent.eth is a public verifier for CommandLayer receipts.

Paste a receipt → resolve signer via ENS → verify hash + signature → get a clear result: VERIFIED or INVALID.

## What it proves
Agents don’t make claims — they produce proof.

## How it works
1. Parse receipt (execution + proof)
2. Canonicalize JSON (json.sorted_keys.v1)
3. Recompute SHA-256 hash
4. Resolve signer from ENS (e.g. runtime.commandlayer.eth → cl.sig.pub, cl.sig.kid)
5. Verify Ed25519 signature (@noble/ed25519)
6. Return VERIFIED / INVALID with reasons

## Demo
- Site: https://www.commandlayer.org
- Verifier: https://www.commandlayer.org/verify.html

## Repos
- Runtime (backend): https://github.com/commandlayer/runtime
- SDK: https://github.com/commandlayer/sdk

## Quickstart
```bash
npm install
npm run dev
