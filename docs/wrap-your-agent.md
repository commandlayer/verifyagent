# Wrap Your Agent

## 1) Bring any agent

Use your existing agent or function. VerifyAgent does not require a specific framework.

## 2) Wrap the action

Capture a normalized action payload:

- signer ENS name
- action verb
- timestamp
- input
- output
- runtime metadata

Canonicalize using `json.sorted_keys.v1`, then SHA-256 hash that canonical JSON.

## 3) Emit a receipt

Sign the hash with an Ed25519 private key and emit:

- `metadata.proof.canonicalization`
- `metadata.proof.hash_sha256`
- `signature.alg`
- `signature.kid`
- `signature.sig`

Reference implementation: `examples/wrapped-agent-demo/demo-agent.js`.

## 4) Verify publicly

Paste the emitted receipt into:

- `public/verify.html` in this repo, or
- https://www.commandlayer.org/verify.html

A valid receipt resolves signer metadata from ENS text records and returns **VERIFIED**.
