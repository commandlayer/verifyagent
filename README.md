# VerifyAgent

VerifyAgent is the public verification layer for CommandLayer receipts and supported signed artifacts. Verification is intentionally scoped: a valid signature proves integrity/provenance for the covered artifact; it does not certify factual truth.

## Factory execution evidence

VerifyAgent recognizes the Machine-Service Factory profile:

`commandlayer.execution-evidence.v1`

For that profile it delegates signature and canonicalization verification to `@commandlayer/runtime-core` and reports:

- `VERIFIED`, `INVALID`, or `INDETERMINATE`;
- execution-integrity/provenance proof scope;
- signer/key binding;
- service/workflow binding;
- payment-separation checks;
- `truth_certified: false`.

### Verification-key resolution

Factory receipts do not choose their own verification-key URL.

When `COMMANDLAYER_RECEIPT_KEY_URL` is configured, VerifyAgent first resolves the exact active `kid + signer_id + Ed25519` key from that configured HTTPS trust-root document. The launch target is:

`https://api.commandlayer.org/.well-known/commandlayer-receipt-keys`

Resolution policy is fail-closed:

- a matching active key from the configured HTTPS trust root is used;
- a reachable trust root with a missing, conflicting, ambiguous, malformed, or private-key-bearing entry is authoritative and is **not** bypassed through ENS;
- ENS may be used only as an availability fallback when the HTTPS trust root is disabled or genuinely unavailable;
- no hardcoded verification key is accepted as a production fallback.

The expected trust-root document profile is `commandlayer.receipt-verification-keys.v1` and each active factory key must identify its `kid`, `signer_id`, `alg`, and public key material.

## Trust model

VerifyAgent distinguishes execution proof from payment proof and factual truth. A successful factory verification means the declared receipt structure, signer binding, canonical signature, service/workflow binding, and payment-separation checks passed. It does not mean the underlying model output or external source claim is true.

## Development

Install and run tests:

```bash
npm ci
npm test
```

The factory adapter intentionally remains compatible with the currently published runtime-core package until the separate runtime-core factory receipt release is approved. Tests inject the new runtime-core factory surface where necessary; no unpublished production package is assumed.

See `.env.example` for the optional canonical factory receipt-key trust-root setting and fixture-only development key configuration.
