.PHONY: test generate check-generated build demo-up demo-verify scoped-verify repository-verify research-build

test: check-generated
	cd gateway && go test -race ./...
	cd controller && go test -race ./...
	python3 tests/integration/database_snapshot_acceptance.py
	python3 tests/integration/recovery_bundle_acceptance.py
	python3 -m unittest discover -s tests/integration -p test_recovery_isolation.py
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
