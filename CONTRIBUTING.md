# Contributing to Identity Bridge zkTLS

Thank you for helping improve Identity Bridge zkTLS. This repository is intended to become public, so contributions should make the project more credible, privacy-preserving, and buildable without overstating what exists today.

## Current Stage

This project is in product design and early implementation planning. Treat `PRD.md` as the canonical scope document until code, deployment scripts, and audits exist.

Do not add claims about production deployments, supported KYC use in regulated settings, legal compliance, audits, Chainlink endorsement, bug bounties, or provider partnerships unless there is verifiable evidence in the repository.

## Contribution Focus

High-value contributions should improve one of these areas:

- Credential schema design, status modeling, TTLs, renewal, and revocation flows.
- zkTLS provider adapter interfaces and test vectors.
- CRE workflow design for proof intake, provider routing, validation, and result submission.
- Confidential-compute and privacy boundaries for raw proof material.
- CCID binding, wallet recovery assumptions, and cross-chain credential propagation through CCIP.
- Integrator SDK examples that handle valid, expired, revoked, unknown, pending, and disputed states safely.
- Public privacy docs, trust-boundary diagrams, and limitations language.

## Product Quality Bar

Contributions should keep the product privacy-first and integrator-safe:

- Expose the minimum useful credential result.
- Never store or emit raw PII, raw TLS transcripts, account handles, documents, or provider responses.
- Make expiry, revocation, freshness, and provider trust visible to integrators.
- Treat legal and compliance claims as out of scope unless reviewed externally.
- Keep docs aligned with the MVP and non-goals in `PRD.md`.

## Engineering Standards

When implementation begins, code contributions should follow these expectations:

- Use Foundry for Solidity contracts unless the repository later standardizes otherwise.
- Pin compiler and dependency versions.
- Add NatSpec for public and external contract interfaces.
- Use role-based access control and scoped pause controls for provider, schema, issue, renewal, revocation, and propagation paths.
- Validate CCIP router, source chain selector, source sender, schema version, nonce, and message type.
- Keep CRE workflow outputs deterministic and avoid logging raw proof material.
- Store hashes, compact enums, or commitments for sensitive fields.
- Use `bigint` for on-chain values in TypeScript workflows and tests.

## Verification Expectations

Use the narrowest useful check first, then broaden.

| Change type | Expected verification |
| --- | --- |
| Docs only | Check links, headings, terminology, and alignment with `PRD.md` |
| Solidity contracts | `forge fmt --check`, unit tests, fuzz tests, and relevant invariant tests |
| CRE workflows | Simulation tests for valid proof, invalid proof, malformed proof, unsupported provider, provider timeout, and no-log privacy assertions |
| CCIP flows | Local simulator tests for propagation, replay, wrong source, wrong schema, stale nonce, and destination pause |
| SDK examples | Compile examples and demonstrate safe handling of all credential states |

If a check cannot run, explain the blocker in the PR instead of presenting the work as fully verified.

## Pull Request Checklist

Before opening a PR:

- The change maps to a requirement, risk, or open question in `PRD.md`.
- Public-facing docs do not include fake deployments, fake providers, fake legal claims, fake audit status, or fake bounty details.
- Privacy-sensitive changes state what data is processed, stored, emitted, logged, and intentionally excluded.
- Tests or verification notes cover the behavior changed.
- New environment variables are documented with placeholders only.
- No secrets, raw proofs, PII, provider credentials, private keys, API keys, or access tokens are committed.

## Commit Style

Use Conventional Commits:

- `feat:` for product behavior
- `fix:` for bug fixes
- `docs:` for documentation
- `test:` for tests
- `refactor:` for internal structure changes
- `security:` for security hardening
- `chore:` for maintenance

## Review Standard

Reviewers should check correctness, scope control, privacy impact, provider trust assumptions, replay resistance, test coverage, and whether the change makes the future public repository more trustworthy.

## License

By contributing, you agree that your contributions will be licensed under the repository's license once one is selected.