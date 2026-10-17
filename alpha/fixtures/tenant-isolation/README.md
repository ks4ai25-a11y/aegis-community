# Trusted tenant-isolation challenge

Declared owner requirement: `authenticated_subject.tenant_id == object.tenant_id`.
Seeded users: red-user/org_red and blue-user/org_blue. Seeded objects: red-object/org_red and blue-object/org_blue. Every value is synthetic.

`lab.VerifyTenant` measures six HTTP outcomes against the vulnerable baseline and one fixed compiled candidate: same-tenant controls for both organisations, both cross-tenant requests, unauthenticated request and missing object. The correct ownership check passes. An incorrect red-only check, deny-all mitigation and unchanged vulnerable application fail. The patch is an illustrative review artifact; arbitrary user/model patches are not executed. Reports reach at most evidence tier T2 (the baseline flaw reproduced in isolation): the candidate is a precompiled variant, not a fix applied to the code under test, so it never earns T3 or T4.

This does not meet the complete C2 application patch workflow. Code checkout identity, disposable VM, source patch compilation, signatures and durable scope/job orchestration remain required.
