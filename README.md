# VerifyAgent

VerifyAgent is a public verifier for machine-action receipts and CLAS Trust Verification payloads.

ENS may be used for signer discovery, key resolution, and agent identity metadata.

VerifyAgent supports CLAS Trust Verification v1 receipts while preserving compatibility with legacy CommandLayer receipts.

VerifyAgent is the reference verifier: paste or submit a receipt, resolve signer identity and verification metadata from ENS, recompute the canonical hash, verify Ed25519 signatures, and return a clear **VERIFIED** or **INVALID** result.

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
3. VerifyAgent resolves signer identity and verification metadata from ENS (`cl.sig.pub`, `cl.sig.kid`, `cl.sig.canonical`, `cl.receipt.signer`).
4. VerifyAgent parses and applies a schema validation phase (legacy or CLAS Trust Verification v1 shape).
5. VerifyAgent canonicalizes + hashes payload, then verifies Ed25519 signature.
6. Result is **VERIFIED** or **INVALID** with explicit checks.

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

## Reference signer profile

- signer: `runtime.commandlayer.eth`
- key id: `vC4WbcNoq2znSCiQ`
- canonicalization: `json.sorted_keys.v1`
- signature algorithm: `ed25519`

## ENS signer records

Known signer records for `runtime.commandlayer.eth`:

- `cl.receipt.signer = runtime.commandlayer.eth`
- `cl.sig.kid = vC4WbcNoq2znSCiQ`
- `cl.sig.pub = ed25519:hhyCuPNoMk4JtEvGEV8F6nMZ4uDO1EcyizPufmnJTOY=`
- `cl.sig.canonical = json.sorted_keys.v1`

VerifyAgent resolves signer keys from ENS TXT records.
Fallback is a local demo fallback for runtime.commandlayer.eth only, mirroring the ENS record structure.
The verification flow is designed to operate against live ENS records.

VerifyAgent is designed to be discoverable as a verifier across agent ecosystems, with ENS supporting signer discovery and identity resolution.

## Validation semantics

`checks.schema_valid` indicates receipt structure validity for the detected mode (`legacy` or `clas_v1`).

`checks.hash_matched` and `checks.signature_valid` indicate cryptographic validity.

- Legacy validity: `hash_matched && signature_valid`
- CLAS v1 validity: `schema_valid && hash_matched && signature_valid`

Full `checks` object:

| Field | Meaning |
|---|---|
| `schema_valid` | Receipt shape matches the detected mode |
| `hash_matched` | Recomputed hash equals stored hash, canonicalization matches ENS |
| `signature_valid` | Ed25519 signature verifies against ENS-resolved public key |
| `signer_resolved` | `cl.sig.pub` and `cl.sig.kid` were resolved from ENS |
| `signer_matched` | `receipt.signer` matches `cl.receipt.signer` from ENS |
| `trust_verb_identified` | A recognized trust verb was found (clas_v1 only) |
| `trust_verb` | Normalized trust verb, or `null` |

The response also includes a `debug` object with `recomputed_hash_sha256`, `expected_hash_sha256`, and `key_id_matched` for diagnostic use.


## CLAS schema bundling

VerifyAgent validates CLAS Trust Verification receipts with JSON Schema using a generated bundle (`src/generated/clas-schema-map.js`).

Schemas are bundled ahead of tests/build to avoid runtime network dependencies.

Regenerate with:

```bash
npm run build:clas-schemas
```
