# Security policy

Aegis Community is an internal alpha with no supported production release. Do not deploy it for real customer traffic until the published release gates pass. See `docs/KNOWN_LIMITATIONS.md` and `docs/IMPLEMENTATION_STATUS.md`.

## Reporting

A maintainer-controlled private security reporting address and repository security advisory channel must be configured before publication. Until then, report findings directly to the operator who supplied this local checkout. Never paste credentials, customer payloads, exploit targets or raw source into public issue trackers. This file does not imply that an invented address is monitored.

Include the affected version, a synthetic reproduction, expected and actual outcomes, and sanitized evidence. Disclosure timing and supported-version policy are release requirements awaiting maintainer ownership.

## Engineering rules

Gateway, deployer, scope, authentication, secret handling and arbitrary code execution changes require an ADR, negative tests and independent review. The author cannot self-approve a security-critical release. Models and scanned source provide untrusted data, never instructions or authority. Production testing requires explicit target ownership and exact scoped approval. Research services receive no gateway or Docker administration socket. User repository code requires a separately reviewed disposable VM boundary.
