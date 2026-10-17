.PHONY: release-evidence mcp-build defence-verify test generate check-generated build demo-up demo-verify scoped-verify repository-verify research-build

test: check-generated
	python3 -m unittest discover -s tests/integration -p test_generated_check.py
	python3 -m unittest discover -s tests/integration -p test_acceptance_assertions.py
	cd gateway && go test -race ./...
	cd controller && go test -race ./...
	python3 tests/integration/database_snapshot_acceptance.py
	python3 tests/integration/recovery_bundle_acceptance.py
	python3 tests/integration/authorizer_enrollment_acceptance.py
	python3 tests/integration/workspace_registry_acceptance.py
	python3 tests/integration/admitted_policy_acceptance.py
	python3 -m unittest discover -s tests/integration -p test_recovery_isolation.py
	python3 -m unittest discover -s tests/integration -p test_ci_engine.py
	python3 -m unittest discover -s tests/integration -p test_packaged_admission.py
	cd alpha && go test -race ./...
	cd tests/integration/scannerchannel && go test -race ./...
	cd shared/source && go test -race ./...
	cd contracts && go test -race ./...
	cd console && npm ci && npm run build

generate:
	python3 scripts/generate_contracts.py
	python3 scripts/generate_research_api.py

check-generated:
	python3 scripts/check_generated.py

build:
	docker compose -f deploy/compose.demo.yaml build

demo-up:
	docker compose -f deploy/compose.demo.yaml up -d

demo-verify:
	python3 tests/integration/demo_acceptance.py

scoped-verify:
	python3 tests/integration/scoped_jobs_acceptance.py

repository-verify:
	python3 tests/integration/repository_acceptance.py

research-build:
	cd alpha && go build -trimpath -o ../bin/aegis-research ./cmd/aegis-research
	cd alpha && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o ../bin/scanner-guard-linux-arm64 ./cmd/scanner-guard
	cd alpha && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o ../bin/scanner-guard-linux-amd64 ./cmd/scanner-guard

broker-build:
	cd alpha && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o ../bin/aegis-scanner-broker ./cmd/aegis-scanner-broker
	cd alpha && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o ../bin/aegis-scan-dispatch ./cmd/aegis-scan-dispatch

engine-authz-build:
	cd alpha && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o ../bin/aegis-engine-authz ./cmd/aegis-engine-authz

engine-relay-build:
	cd alpha && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o ../bin/aegis-engine-relay ./cmd/aegis-engine-relay

mcp-build:
	cd controller && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o ../bin/aegis-mcp ./cmd/aegis-mcp

# Live defence-plane suites against a running stack (defaults: the demo on 7410/8080).
# Override AEGIS_CONSOLE_URL, AEGIS_GATEWAY_URL, AEGIS_COMPOSE_FILES and AEGIS_CREDENTIAL for another install.
defence-verify: mcp-build
	cd tests/integration && python3 multi_site_acceptance.py
	cd tests/integration && python3 detector_acceptance.py
	cd tests/integration && python3 assessment_acceptance.py
	cd tests/integration && python3 mcp_acceptance.py
	cd tests/integration && python3 remediation_acceptance.py
	python3 tests/negative-security/defence_negative.py

release-evidence:
	python3 scripts/release/release_evidence.py
