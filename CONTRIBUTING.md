# Contributing

Build instructions are in README.md. Use Go 1.27.1 and Node 22 with the checked-in module sums and npm lockfile. Do not change dependency pins silently. Go modules in `gateway`, `controller` and `alpha` are independent; the gateway must not import AI or research orchestration.

Run relevant tests and include real evidence with the change. Security-sensitive changes need an ADR and independent review. Never mark a release gate passed without its required evidence. Preserve source licensing and add third-party notices before redistribution. Scanner output, source comments and AI output are untrusted data.

Use synthetic fixtures only in automated tests. Do not connect test jobs to public targets or production data. Do not execute repository install scripts during inventory/scanning. Do not mount a Docker socket into a service.

## Licence and contributor agreement

Aegis Community is source-available under the [Business Source License 1.1](LICENSE). Contributions are accepted only under the [Contributor Licence Agreement](CLA.md), so that the project can also be offered commercially. New source files start with `// SPDX-License-Identifier: BUSL-1.1` (or the comment syntax of the file type).

Contribution branches, issue templates and review ownership will be established with the maintainer before public launch.
