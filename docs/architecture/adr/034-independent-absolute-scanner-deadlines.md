# ADR 034: Independent absolute scanner deadlines

Status: implemented in the current fixed worker/executor and rebuilt Linux guard. Independent cleanup verification/release remains unfinished.

## Decision

The PID-1 scanner guard now requires a canonical UTC absolute deadline as well as the fixed tool and bounded duration. The native worker passes its original controller job deadline. A standalone operator scan derives one finite launch deadline locally. The executor rejects expired or excessively distant configured deadlines before accessing the snapshot or Docker, and rechecks cancellation/expiry after prelaunch authorization before sending the run command.

A delayed Docker start cannot obtain a fresh full-duration scanner window: the guard rejects an expired deadline with exit 124 before reading the input manifest/source or spawning the fixed tool. Invalid or missing deadline arguments refuse with exit 125. A valid run's timer uses the earlier of the tool budget and the remaining original deadline, covers source/rule validation and rechecks before process creation. Process-group kill and PID-1 exit still stop descendants; output bounds and exact-container cleanup remain in force. The host Docker-call deadline also cannot exceed the absolute execution deadline, while independent cleanup has its own bounded allowance.

The guard accepts only canonical UTC RFC 3339 timestamps within fifteen minutes, matching the current maximum queue authority window. Time interpretation trusts the local host clock. This is not remote attestation or protection against a host administrator changing time or binaries.

## Cleanup implications and compatibility

This closes the current guard's relative-runtime late-start gap. It does not prove the absence of a queued Docker request, container, mount or workspace. Reservations/launches/receipts/results remain intent or worker evidence; controller admission stays held. A delayed container can still exist briefly while its guard refuses. Independent trusted engine/registry verification, late-request exclusion and separately authorized release remain necessary.

Rebuild both Linux guard architectures and the native CLI together. Old two-argument guards do not implement absolute expiry, and the new guard refuses the old invocation. Guard binary hashes change in actual receipts. Existing immutable evidence is not reinterpreted or rewritten. No claim is made that historical launch records without independently identified guard provenance authorize cleanup release; the controller protocol does not independently attest guard bytes or the deadline argument yet.

## Verification

Unit tests cover start exactly at/after expiry, partial remaining budget, tool-duration cap, canonical UTC, invalid duration and excessive windows. Executor tests refuse expired deadlines before source/Docker. Real owned non-root network-none containers mount only the rebuilt guard, with no source or manifest: expired startup exits 124 and malformed time exits 125, proving refusal precedes source access or scanner creation. Native actual scanner fixtures verify unchanged result/receipt handling under the new guard. See `docs/evidence/scanner-absolute-deadline-acceptance.json`.
