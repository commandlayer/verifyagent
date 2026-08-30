# Changelog

## 0.3.0 - 2026-08-30
- Added independent verification for `commandlayer.execution-evidence.v1` Machine-Service Factory receipts.
- Added HTTPS factory trust-root resolution with exact `kid` + `signer_id` matching and fail-closed authoritative failures.
- Added execution-integrity/provenance result mapping with `truth_certified: false`.
- Added explicit `INDETERMINATE` behavior when the runtime-core factory surface or signer key is unavailable.
- Pinned the cutover build to the exact released runtime-core merge commit `9a87bb7b945080e5e0882368a2f80fed66944d7d` until the npm package receives its one-time registry bootstrap.
- Exported `./factory-execution-evidence` and `./factory-key-document` so the public CommandLayer deployment can consume the actual VerifyAgent verifier implementation.

## 0.2.1 - 2026-04-28
- Added deterministic real Ed25519 verification fixtures for tests (`test/fixtures/real-signed-receipt.json`) and updated tests to validate real signature behavior (including explicit rejection of `DEMO_SIGNATURE_VALID_FOR_HASH`).
- Replaced example receipts with real signed receipt-format data and tampered counterpart that fails hash matching.
- Documented TODO to swap in a publicly distributable production Runtime-signed receipt when available.

## 0.2.0 - 2026-04-28
- Added real ENS-resolved Ed25519 verification flow (with labeled fallback for `runtime.commandlayer.eth` when live ENS text resolution is unavailable in browser).
- Added wrapped agent demo (`examples/wrapped-agent-demo`) that emits signed receipts.
- Removed placeholder signature verification and removed acceptance of `DEMO_SIGNATURE_VALID_FOR_HASH`.

## 0.1.0 - 2026-04-28
- Initialized VerifyAgent as its own public verifier repository for receipts produced by ENS-named agents.
