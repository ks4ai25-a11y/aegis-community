FROM golang:1.27.1-alpine3.23@sha256:0908ac9b9319e09d7c238aabe914e0395c51d63c4e3d0ae8c554fda9158a5769 AS build
WORKDIR /src/alpha
COPY shared/source/ /src/shared/source/
COPY alpha/go.mod alpha/go.sum ./
RUN go mod download
COPY alpha/ ./
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/aegis-research ./cmd/aegis-research && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o /guards/scanner-guard-linux-amd64 ./cmd/scanner-guard && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -o /guards/scanner-guard-linux-arm64 ./cmd/scanner-guard
FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
RUN addgroup -g 10001 aegis && adduser -D -u 10001 -G aegis aegis && mkdir -p /run/scanner /run/worker-credential /run/engine /opt/aegis/bin /opt/aegis/alpha/rules /opt/aegis/repositories && chmod 700 /run/scanner /run/worker-credential && chown 10001:10001 /run/scanner /run/worker-credential
COPY --from=build /out/aegis-research /usr/local/bin/aegis-research
COPY --from=build /guards/ /opt/aegis/bin/
COPY tools/scanners.lock.json /opt/aegis/tools/scanners.lock.json
COPY alpha/rules/ /opt/aegis/alpha/rules/
USER 10001:10001
ENV DOCKER_HOST=unix:///run/engine/docker.sock DOCKER_CONTEXT=""
ENTRYPOINT ["aegis-research"]
