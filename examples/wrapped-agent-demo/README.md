# Wrapped Agent Demo

This demo wraps a simple agent call, emits a signed CommandLayer-style receipt, and writes it to `out/receipt.json`.

## Run

```bash
npm install
npm run demo
```

Set environment variables first (copy from `.env.example`):

- `CL_RECEIPT_SIGNER` (default `runtime.commandlayer.eth`)
- `CL_KEY_ID` (default `vC4WbcNoq2znSCiQ`)
- `CL_CANONICAL_ID` (default `json.sorted_keys.v1`)
- `CL_PRIVATE_KEY_PEM` (required, PKCS8 Ed25519 PEM)

The script prints:

- `Agent ran`
- `Receipt created`
- `Verify at https://www.commandlayer.org/verify.html`
