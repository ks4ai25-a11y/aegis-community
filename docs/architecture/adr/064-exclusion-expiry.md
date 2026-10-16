# ADR 064: Owner-approved exclusion expiry

Status: implemented; unit-tested and validated on a local stack.

## Problem

Exclusions added to silence a false positive tend to outlive their purpose and permanently weaken inspection. The v4 policy lifecycle ends in `rolled_back|expired`, but nothing expired.

## Decision

`Exclusion` gains optional `expires_at` (UTC RFC 3339 to the second; omitted fields keep existing digests). Preview refuses a candidate that introduces an already-expired exclusion. Proposed exclusions (ADR 060) expire after 30 days by default.

`controller/internal/expiry` runs every minute in the controller. When any active exclusion has expired it builds the stricter revision without it (parent = active digest, requested by `system:expiry`), runs the same isolated fixture as an owner preview, stores the report under the installation owner, stages the candidate and activates it through the normal deployer path. The canary (ADR 063) then checks the live gateway. If the fixture does not pass, nothing changes and an incident records that the expired exclusion could not be removed safely.

Removing an exclusion only increases inspection, and the owner approved the expiry when they approved the exclusion; the fixture gate and the canary remain the safety checks. Legitimate traffic that depended on the exclusion may start matching again, which is why expiry is explicit and visible in the policy.

## Validation

Expiry tests cover removal after a fixture pass (with correct parent and staged state), a failing fixture that keeps the exclusion and raises an incident, and unexpired policies that are left alone. Policy validation refuses non-UTC or malformed timestamps. On a local stack, a 90-second exclusion was removed automatically by `system:expiry` with the correct parent revision and the canary passed afterwards; an already-expired exclusion was refused at preview.
