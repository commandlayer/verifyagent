# Changelog

## 0.2.1 - 2026-04-28
- Added deterministic real Ed25519 verification fixtures for tests (`test/fixtures/real-signed-receipt.json`) and updated tests to validate real signature behavior (including explicit rejection of `DEMO_SIGNATURE_VALID_FOR_HASH`).
- Replaced example receipts with real signed receipt-format data and tampered counterpart that fails hash matching.
- Documented TODO to swap in a publicly distributable production Runtime-signed receipt when available.

## 0.2.0 - 2026-04-28
- Added real ENS-resolved Ed25519 verification flow (with labeled fallback for `runtime.commandlayer.eth` when live ENS text resolution is unavailable in browser).
- Added wrapped agent demo (`examples/wrapped-agent-demo`) that emits signed receipts.
- Removed placeholder signature verification and removed acceptance of `DEMO_SIGNATURE_VALID_FOR_HASH`.

## 0.1.0 - 2026-04-28
- Initialized VerifyAgent as its own public Commons/MIT repository for verifying CommandLayer receipts.
