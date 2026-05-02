# Wrap Your Agent

## VerifyAgent positioning

VerifyAgent.eth is the public verifier for CommandLayer receipts.

- Live verifier UI: https://www.commandlayer.org/verify.html
- API verifier: https://www.commandlayer.org/api/verify
- Callable VerifyAgent: https://www.commandlayer.org/api/agents/verifyagent

## Install the SDK

```bash
npm install @commandlayer/agent-sdk
```

- SDK npm: https://www.npmjs.com/package/@commandlayer/agent-sdk
- SDK GitHub: https://github.com/commandlayer/agent-sdk

## Current flow

Agent action
→ `@commandlayer/agent-sdk` wraps action
→ signed CommandLayer receipt emitted
→ VerifyAgent verifies receipt
→ **VERIFIED** or **INVALID**

## Quickstart

```js
import { CommandLayer } from "@commandlayer/agent-sdk";

const cl = new CommandLayer({
  agent: "runtime.commandlayer.eth",
  privateKey: process.env.CL_PRIVATE_KEY_PEM,
  keyId: "vC4WbcNoq2znSCiQ",
  verifierUrl: "https://www.commandlayer.org/api/verify"
});

const result = await cl.wrap("summarize", async () => {
  return { summary: "hello world" };
});

console.log(result.output);
console.log(result.receipt);

const verified = await cl.verify(result.receipt);
console.log(verified.status);
```

## What `wrap()` returns

`wrap()` returns:

- `output`: the action result from your wrapped function
- `receipt`: a signed CommandLayer receipt

The `receipt` contains:

- signer
- verb
- input
- output
- execution
- `metadata.proof.hash_sha256`
- signature

## Verification behavior

Verification checks:

- canonical hash
- Ed25519 signature
- ENS signer metadata (when available)

If `input` or `output` is tampered after signing, verification returns **INVALID**.

## Reference implementation

`examples/wrapped-agent-demo` remains a reference implementation for how wrapping works end-to-end, but the primary developer path is the published `@commandlayer/agent-sdk` package.
