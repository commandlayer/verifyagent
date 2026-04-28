# VerifyAgent.eth

**VerifyAgent.eth proves what agents actually did using signed, ENS-resolved receipts.**

VerifyAgent is a simple, public verifier for CommandLayer agent execution receipts. Paste a receipt, resolve signer identity through ENS, rebuild the canonical hash, verify the signature, and get a clear **VERIFIED** or **INVALID** result.

## Why VerifyAgent exists

VerifyAgent makes receipts auditable by anyone. It is intentionally lightweight and demo-friendly so teams, researchers, and hackathon builders can inspect proof artifacts without relying on private infrastructure.

## Why ENS matters

ENS gives a human-readable signer identity (for example `runtime.commandlayer.eth`) and a discoverable place for signer key metadata (for example `cl.sig.pub`).

In production, VerifyAgent resolves the signer through ENS and validates that the key source is trustworthy and transparent.

> Local demo note: ENS resolution is currently shown as a clear stub in this repository.

## Demo flow

1. Load sample receipt
2. Verify → **VERIFIED**
3. Tamper receipt
4. Verify → **INVALID**

## Architecture split

- **VerifyAgent** = public verifier / Commons / MIT
- **CommandLayer SDK** = receipt tooling
- **Runtime** = executes actions and emits receipts
- **Commercial** = hosted APIs, x402, indexing, dashboards
- **Agent Cards** = identity/capability metadata

## Install & run

```bash
npm install
npm run dev
```

Then open:

- `http://localhost:4173/public/verify.html`

## Scope and license

This repository is the public **Commons / MIT** verifier surface.

- It does **not** include commercial hosted APIs
- It does **not** include x402 implementation
- It does **not** include dashboard/auth/org-account code

## CommandLayer links

- CommandLayer: https://www.commandlayer.org
- Runtime repo: https://github.com/commandlayer/runtime
- SDK repo: https://github.com/commandlayer/sdk
