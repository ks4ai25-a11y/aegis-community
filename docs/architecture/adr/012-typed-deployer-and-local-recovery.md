# ADR 012: Typed deployer and gateway-local recovery

Status: implemented for the bundled internal demo; independent security review pending.

The v4 manual requires separation between the web controller and raw gateway administration. The controller now mounts only a dedicated deployer Unix socket. The deployer runs with no network, no controller database and no Docker socket. It owns the gateway admin socket and a separate policy volume. Its API exposes status, typed validation and compare-and-swap application; it cannot accept Caddy JSON, arbitrary paths, origins, directives or shell commands. The compiler restricts this alpha to the bundled demo site and a fixed upstream.

On confirmed reload the deployer fsyncs and atomically renames the active Caddyfile in its own volume. The gateway mounts that volume read-only and starts from that file after restart, without querying the controller. A persistence failure is an unconfirmed application, not success. Controller startup reconciles its durable active policy with the gateway revision. Recovery of a crash between gateway application and controller commit still needs the broader fault-injection gate.

The origin and verifier remain on internal Docker networks. Gateway and controller additionally use a Docker bridge to support loopback published ports on Docker Desktop. Those ports bind 127.0.0.1 only. This does not establish an OS firewall guarantee or production network configuration. The fixture worker has no ingress bridge and no privileged socket.

Risk: service images currently share a build artifact, although mounts and network privileges differ. Separate minimal runtime images and signed deployer receipts remain release work. A compromised controller can request a policy within the deliberately narrow demo schema; stronger per-action approval capability validation is required before supporting production origins.
