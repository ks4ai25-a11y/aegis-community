# ADR-011: Adopt the OSS-first v4 research plane

Status: implementation decision; independent security review pending.

The owner replaced v3.2 with v4 on 12 October 2026. The v4 master specification takes precedence. Compatible gateway/controller work is retained; source research is a distinct off-path capability.

Scanners run as separately installed pinned tools against an explicitly mounted read-only repository, without package installation or repository script execution. Findings contain provenance and distinguish static tool claims from application-level reproduction. Untrusted application execution requires a separate disposable lab/VM; the web controller receives no Docker socket. Only bundled trusted synthetic fixtures may execute in the initial local Docker lab.

The synthetic tenant-isolation demo uses explicit ownership semantics and two test principals. A generic WAF is not an ownership authorization fix. Code patches are reviewed artifacts; no merge or production deployment follows automatically. A failing benign control rejects a candidate.

Before release: scope escape, scanner output, canary redaction, fault recovery and independent reviewer gates must pass.
