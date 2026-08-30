# CommandLayer Repository Instructions

This repository is part of the CommandLayer protocol stack.

## Repo role

`commandlayer/verifyagent` is the public verifier implementation, UI, and API layer for CommandLayer receipts.

This repository owns:

- public receipt verification UX
- verifier API behavior where present
- verification result presentation
- sample and tampered receipt demos
- verifier-specific docs and examples
- public trust-surface behavior for `verifyagent.eth`

This repository does not own CLAS schema truth, core cryptographic semantics, runtime execution, SDK wrapping behavior, MCP transport behavior, commercial pricing, or the main CommandLayer website.

## Hard rules

- Do not guess.
- Do not publish packages.
- Do not merge pull requests.
- Do not mark a receipt as `VERIFIED` unless all required checks pass.
- Do not mock, skip, simulate, or weaken Ed25519 verification.
- Do not bypass hash verification.
- Do not hide failed verification behind positive UI language.
- Do not hardcode production public keys as the only verification path.
- Do not introduce placeholders, TODOs, skipped tests, or hardcoded secrets.
- Do not confuse sample/demo receipts with live verification output.
- Do not change verifier semantics without referencing the CLAS stack contract.

## Protocol requirements

VerifyAgent behavior MUST align with the canonical stack contract in `commandlayer/clas`:

- canonicalization ID: `json.sorted_keys.v1`
- hash algorithm: SHA-256
- signature algorithm: Ed25519
- receipts include required proof fields
- verifier responses preserve `ok`, `status`, `checks`, and `errors` semantics
- `status: VERIFIED` is only valid when schema, canonical hash, signature, and signer checks pass
- invalid receipts fail closed

## Before editing

1. Inspect `README.md`, public verifier files, API files, examples, fixtures, tests, docs, and `.env.example` where present.
2. Identify whether the change affects verification logic, UI status display, API response shape, fixtures, docs, tests, or demo behavior.
3. Compare the change against the CLAS stack contract.
4. Make the smallest safe change.
5. Run build, test, typecheck, lint, and verifier fixture checks if available.
6. Report changed files, commands run, results, and remaining risks.

## Verification rules

- Schema failure MUST prevent verified status.
- Hash mismatch MUST prevent verified status.
- Invalid signature MUST prevent verified status.
- Missing signer key MUST prevent verified status.
- Unsupported algorithms MUST prevent verified status.
- Malformed proof objects MUST prevent verified status.
- UI and API status MUST agree.
- Tampered examples MUST display invalid results.
- Sample receipts MUST be labeled clearly when not produced live.

## Test requirements

Changes to verification logic, UI status, API responses, or fixtures SHOULD include tests for:

- valid receipt verifies
- tampered payload fails
- tampered signature fails
- missing proof fails
- missing signer key fails
- unsupported algorithm fails
- UI/API status consistency
- sample fixture validity
- tampered fixture invalidity

## Review focus

When reviewing changes, focus on:

- false VERIFIED states
- UI/API mismatch
- sample/live ambiguity
- mocked verification
- skipped tests
- hardcoded secrets or keys
- receipt proof field mismatch
- schema drift
- README claims not backed by implementation
- security headers and public page safety

## Output format

For every task, report:

1. Summary
2. Files changed
3. Checks run
4. Results
5. Risks remaining
6. Follow-up recommendations
