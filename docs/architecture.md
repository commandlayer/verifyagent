# VerifyAgent Architecture

VerifyAgent.eth is the public verifier for receipts produced by ENS-named agents.

## Responsibilities

- **VerifyAgent** verifies receipts.
- **SDK (`@commandlayer/agent-sdk`)** creates signed receipts.
- **ENS** resolves signer identity and verification metadata from TXT records (`cl.sig.pub`, `cl.sig.kid`, `cl.sig.canonical`, `cl.receipt.signer`).

## Role boundaries

- VerifyAgent answers: "Is this receipt valid?"
- SDK answers: "How do developers create receipts?"

## Repository scope

This repository contains verification UX and core verification logic. It does not create receipts.

## Source modules

| Module | Responsibility |
|---|---|
| `src/verify.js` | Orchestrates full verification pipeline |
| `src/schema.js` | Detects receipt mode and validates shape |
| `src/ens.js` | Resolves signer keys from ENS TXT records |
| `src/canonicalize.js` | Deterministic JSON canonicalization (`json.sorted_keys.v1`) |
| `src/crypto.js` | SHA-256 hashing and Ed25519 signature verification |
| `src/tamper.js` | Mutates a receipt for tamper-demonstration fixtures |

## Receipt modes

VerifyAgent detects two receipt shapes:

- **`legacy`**: base receipt shape. Valid when `hash_matched && signature_valid`.
- **`clas_v1`** (CLAS Trust Verification v1): extends legacy with `version`, `family`, and a `trust_verb`. Valid when `schema_valid && hash_matched && signature_valid`.

Mode is detected from indicators in `receipt.version`, `receipt.family`, `receipt.metadata.family`, `receipt.metadata.version`, and `receipt.metadata.proof.trust_verb` / `trustVerb` / `trust`.

## Canonical payload

The fields hashed during verification:

```
signer, verb, input, output, execution, ts
```

These are extracted, recursively sorted by key (`json.sorted_keys.v1`), and serialized to JSON before SHA-256 hashing.

## Trust verbs

Recognized trust verbs for CLAS v1 receipts:

`verify`, `authenticate`, `authorize`, `attest`, `sign`, `permit`, `grant`, `approve`, `reject`, `endorse`

The verb is normalized to lowercase before matching.

## ENS resolution

VerifyAgent resolves four TXT records per signer:

- `cl.sig.pub` — Ed25519 public key (`ed25519:<base64>`)
- `cl.sig.kid` — key identifier
- `cl.sig.canonical` — expected canonicalization scheme
- `cl.receipt.signer` — authoritative signer ENS name

If live ENS resolution fails and the signer is `runtime.commandlayer.eth`, a local fallback mirrors the known ENS records for that name only. Any other signer that fails live resolution returns `not resolved`.

## Verification response

```json
{
  "valid": true,
  "status": "VERIFIED",
  "signerEns": "runtime.commandlayer.eth",
  "keyId": "vC4WbcNoq2znSCiQ",
  "publicKeySource": "live ENS text record",
  "canonicalization": "json.sorted_keys.v1",
  "checks": {
    "schema_valid": true,
    "hash_matched": true,
    "signature_valid": true,
    "signer_resolved": true,
    "signer_matched": true,
    "trust_verb_identified": true,
    "trust_verb": "verify"
  },
  "debug": {
    "recomputed_hash_sha256": "<hex>",
    "expected_hash_sha256": "<hex>",
    "key_id_matched": true
  }
}
```

| Field | Meaning |
|---|---|
| `schema_valid` | Receipt matches the detected mode shape (legacy or clas_v1) |
| `hash_matched` | Recomputed hash equals `metadata.proof.hash_sha256` and canonicalization matches ENS record |
| `signature_valid` | Ed25519 signature over the hash hex verifies against the resolved public key |
| `signer_resolved` | `cl.sig.pub` and `cl.sig.kid` were resolved from ENS |
| `signer_matched` | `receipt.signer` matches `cl.receipt.signer` from ENS |
| `trust_verb_identified` | A recognized trust verb was found (meaningful for clas_v1 only) |
| `trust_verb` | Normalized trust verb value, or `null` |
| `debug.recomputed_hash_sha256` | Hash computed by VerifyAgent over the canonical payload |
| `debug.expected_hash_sha256` | Hash stored in `receipt.metadata.proof.hash_sha256` |
| `debug.key_id_matched` | Whether `receipt.signature.kid` matched the ENS-resolved key id |

## Canonical values

- signer: `runtime.commandlayer.eth`
- key id: `vC4WbcNoq2znSCiQ`
- canonicalization: `json.sorted_keys.v1`
- signature algorithm: `ed25519`
