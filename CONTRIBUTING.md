# Contributing to Identity Bridge zkTLS

Thank you for helping improve Identity Bridge zkTLS. This project is intended to become practical, production-grade privacy-preserving credential infrastructure, not a prototype.

## Current Stage

The repository is in product and architecture design. Treat `PRD.md` as the canonical product specification and `ENGINEERING_SPEC.md` as the engineering build contract.

Do not add claims about production deployments, supported regulated use, legal compliance, audits, Chainlink endorsement, bug bounties, or provider partnerships unless there is verifiable evidence in the repository.

## Contribution Focus

High-value contributions improve the full product path:

- Credential schemas, lifecycle states, TTLs, renewal, dispute, and revocation flows.
- Provider registry and zkTLS/compliance provider adapter interfaces.
- Chainlink workflow proof intake, validation, result submission, and propagation.
- Confidential processing and no-log privacy boundaries.
- CCID binding, wallet recovery assumptions, and CCIP credential propagation.
- SDK and portal behavior for safe status handling.
- Privacy model, provider guide, operations runbooks, and threat-model coverage.

## Product Quality Bar

- Build toward the production credential network described in `PRD.md`.
- Use staged release gates for safety, not reduced product ambition.
- Never store or emit raw PII, raw TLS transcripts, account handles, documents, provider responses, or raw proofs.
- Make expiry, revocation, freshness, provider status, and destination state explicit.
- Keep docs aligned with the full product PRD, engineering spec, and production readiness gates.

## Verification Expectations

| Change type | Expected verification |
| --- | --- |
| Docs only | Check terminology, links, and alignment with `PRD.md` and `ENGINEERING_SPEC.md` |
| Contracts | Formatting, unit tests, fuzz tests, and relevant invariant tests |
| Workflows | Tests for valid proof, invalid proof, malformed proof, unsupported provider, timeout, and no-log privacy assertions |
| CCIP flows | Tests for propagation, replay, wrong source, wrong schema, stale nonce, and destination freshness |
| SDK/portal | Tests showing safe handling of valid, expired, revoked, unknown, pending, suspended, and disputed states |

If a check cannot run, document the blocker in the PR.

## Pull Request Checklist

- Change maps to `PRD.md` or `ENGINEERING_SPEC.md`.
- Public docs avoid fake deployments, fake providers, fake legal claims, fake audits, and fake bounty details.
- Privacy-sensitive changes state what data is processed, stored, emitted, logged, and intentionally excluded.
- Tests or verification notes cover the behavior changed.
- New environment variables use placeholders only.
- No secrets, raw proofs, PII, provider credentials, private keys, API keys, or access tokens are committed.

## Commit Style

Use Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `security:`, or `chore:`.

## License

By contributing, you agree that your contributions will be licensed under the repository's license once one is selected.
