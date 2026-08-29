# Rail-neutral factory execution receipts

VerifyAgent supports the Machine-Service Factory execution receipt profile `commandlayer.execution-evidence.v1` through `src/verify-factory.js`.

The profile is intentionally independent of ENS, ERC-8004, x402 and settlement payloads. Runtime-core owns canonicalization, Ed25519 signing and verification. VerifyAgent supplies an independent verification surface and does not duplicate the cryptographic/profile implementation.

Verification keys are resolved through one of three adapter-neutral inputs:

- `publicKeyPemOrDer`
- `publicKeysByKid`
- `resolvePublicKey(proof)`

A `VERIFIED` result means the signed service/execution envelope has valid cryptographic integrity/provenance under the supplied key. It does **not** mean the service output is factually true.

The existing CLAS/ENS receipt paths remain compatibility/specialized profiles. They are not prerequisites for the rail-neutral factory receipt.

## Cross-repo contract

The canonical implementation is in draft `commandlayer/runtime-core#29`:

- `signFactoryExecutionReceipt()`
- `verifyFactoryExecutionReceipt()`
- `FACTORY_EXECUTION_RECEIPT_PROFILE`
- `FACTORY_EXECUTION_PROOF_COVERS`

The VerifyAgent integration branch pins the exact runtime-core draft commit until that API is approved and published. A follow-on dependency update should replace the git pin with the released package version before production.
