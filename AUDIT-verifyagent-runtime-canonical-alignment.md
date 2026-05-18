# AUDIT: verifyagent runtime canonical alignment

## 1) Current rating
**3/10 (high risk misalignment).**

VerifyAgent is still centered on legacy proof fields and local crypto verification paths, not the canonical runtime receipt envelope and runtime-core verifier contract.

## 2) Target rating
**9/10 (release-ready alignment).**

Target means VerifyAgent delegates canonical proof verification to `verifyCommandLayerReceipt()` from `commandlayer/runtime-core`, accepts the new proof envelope natively, and treats legacy support as explicit compatibility mode (or removed by policy).

## 3) Can VerifyAgent verify current runtime receipts?
**Not reliably for canonical runtime receipts as defined in this audit prompt.**

Current verifier expects legacy-style values such as:
- `metadata.proof.canonicalization`
- `metadata.proof.hash_sha256`
- receipt-level `signature.alg/kid/sig`

It does **not** require/consume the canonical nested shape:
- `metadata.proof.hash.alg/value`
- `metadata.proof.signature.alg/value/kid`

Therefore canonical runtime receipts can fail or be partially misinterpreted unless they also carry backward-compatible legacy fields.

## 4) Proof shape mismatches
### Expected canonical envelope
- `metadata.proof.canonicalization`
- `metadata.proof.hash.alg = "SHA-256"`
- `metadata.proof.hash.value`
- `metadata.proof.signature.alg = "Ed25519"`
- `metadata.proof.signature.value`
- `metadata.proof.signature.kid`

### Observed VerifyAgent assumptions
- Hash read from `metadata.proof.hash_sha256` only.
- Signature read from `metadata.proof.signature` or `metadata.proof.signature_b64` or top-level `signature.sig`.
- KID read from `metadata.proof.kid` or top-level `signature.kid`.
- Canonical ID aliases include `metadata.proof.canonical` and `metadata.proof.canonicalization`.

Result: parser/validator is tuned for old/bridge fields and does not model the canonical nested hash/signature objects.

## 5) Verifier result shape mismatches
Current result contract exposes booleans/debug fields tied to local logic:
- `checks.hash_matched`
- `checks.signature_valid`
- `debug.recomputed_hash_sha256`
- `debug.expected_hash_sha256`

No explicit pass-through/normalization of runtime-core canonical verifier output contract is present (e.g., no imported `verifyCommandLayerReceipt()` result mapping).

## 6) Duplicate crypto/proof logic inventory
VerifyAgent currently contains local cryptographic authority logic that should be runtime-core-owned:
1. Local canonical payload derivation (`canonicalReceiptPayload`).
2. Local canonicalization and SHA-256 recomputation.
3. Local Ed25519 public key import and signature verification.
4. Local proof extraction with multi-format fallbacks.
5. Local mode detection gating cryptographic behavior (`isV110` branch).

This creates drift risk against runtime/runtime-core canonical semantics.

## 7) Test coverage gaps
Existing tests heavily cover legacy/hash_sha256 and local verifier behavior, but gaps remain:
- No tests pinned to canonical nested `metadata.proof.hash.*` + `metadata.proof.signature.*` envelope.
- No tests asserting integration with `verifyCommandLayerReceipt()`.
- No tests for algorithm casing strictness (`Ed25519` vs `ed25519`, `SHA-256` vs `sha256`).
- No explicit negative tests for missing canonical hash/signature subfields in the new shape.
- Tamper tests are legacy-oriented and do not validate runtime-core error/result semantics.

Also, the current test run fails before coverage executes due to duplicate AJV schema registration.

## 8) Files likely affected
- `src/verify.js` (core orchestration and proof extraction)
- `src/schema.js` (shape validation assumptions)
- `src/crypto.js` (local crypto authority to de-scope)
- `schemas/clas/trust-verification/_shared/proof.schema.json` (proof contract)
- `src/generated/clas-schema-map.js` (regenerated artifacts)
- `test/verify.test.js` (test contract + fixtures)
- `test/fixtures/*.json` and `examples/*.json` (legacy shape fixtures)
- `README.md`, `docs/architecture.md`, `docs/wrap-your-agent.md` (claims and examples)

## 9) Safe implementation order
1. **Adopt runtime-core as cryptographic authority**
   - Import/use `verifyCommandLayerReceipt()` in verification pipeline.
2. **Define canonical proof schema first**
   - Add strict schema for nested `hash` and `signature` objects with required alg/value/kid.
3. **Map verifier result contract**
   - Normalize runtime-core output into VerifyAgent API/UI response (or expose directly).
4. **Retire duplicate local crypto path**
   - Remove/disable local hash/signature verification for canonical mode.
5. **Legacy compatibility policy decision**
   - Explicitly gate legacy receipt support behind compatibility path/flag.
6. **Fixture + test migration**
   - Add canonical fixtures and tampered variants based on new envelope.
7. **Docs/UI/API alignment**
   - Update claims, field names, and verified-state criteria.

## 10) Release blockers
1. No `verifyCommandLayerReceipt()` integration.
2. Canonical proof envelope unsupported as first-class schema.
3. Legacy fields treated as primary inputs (`hash_sha256`, top-level signature fields).
4. Crypto verification duplicated locally (drift risk).
5. Docs currently claim reference-verifier authority using local logic.
6. Test suite currently failing (AJV duplicate schema id), reducing confidence.

## 11) Recommendation: safe public trust surface now?
**No. Not yet safe to treat as a public trust surface for current runtime canonical receipts.**

Reason: verifier and schema contracts are not aligned to runtime-core canonical proof authority, and local crypto/proof logic can diverge from runtime/runtime-core semantics.

---

## Detailed findings against requested audit checklist

### 1. Current verifier imports
- No import of `verifyCommandLayerReceipt()`.
- Verifier imports local crypto helpers (`sha256Hex`, `verifyHashHexSignature`, `verifyCanonicalSignature`).

### 2. Local hash rebuilding
- Hash is recomputed locally from canonicalized payload and compared to `metadata.proof.hash_sha256`.

### 3. Local Ed25519 verification
- Public key is imported and signature checked locally via WebCrypto Ed25519.

### 4. Local proof shape assumptions
- Proof extraction supports mixed legacy fields, not canonical nested objects.

### 5. Legacy fields usage
- Legacy/bridge fields present in parsing and docs/tests:
  - `proof.canonical` (alias use)
  - `proof.hash_sha256` (primary)
  - `proof.signature_b64` (fallback)
  - plus top-level signature fallback.
- Requested fields `proof.alg` and `proof.canonical_id` are not prominent, but the system still depends on legacy-era equivalents.

### 6. Signature algorithm casing issues
- Runtime target expects `Ed25519`; fixtures/docs commonly show lowercase `ed25519`.
- No strict canonical algorithm casing guard for nested canonical envelope because nested envelope is not implemented.

### 7. Sample fixtures using old proof shape
- Fixtures include `canonicalization` + `hash_sha256` and top-level signature block.

### 8. UI states that show VERIFIED without full checks
- Not fully audited in UI rendering code in this pass, but verifier returns `VERIFIED` from local checks without runtime-core authority.

### 9. API response shape mismatch
- Response shape reflects local check/debug booleans rather than runtime-core canonical verifier contract.

### 10. Tampered receipt behavior
- Legacy tamper behavior exists and generally returns `INVALID`, but it validates local pipeline semantics, not runtime-core canonical semantics.

### 11. ENS key resolution behavior
- ENS resolution is mandatory and short-circuits to `INVALID` on failure.
- Still paired with local cryptographic verification path.

### 12. README/docs claims
- README and architecture docs describe local canonicalize/hash/signature pipeline as reference behavior, which is no longer the correct authority model if runtime-core is canonical.
