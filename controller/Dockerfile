FROM golang:1.27.1-alpine3.23@sha256:0908ac9b9319e09d7c238aabe914e0395c51d63c4e3d0ae8c554fda9158a5769 AS gateway-build
WORKDIR /src
COPY gateway/go.mod gateway/go.sum ./
RUN go mod download
COPY gateway/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/caddy ./cmd/caddy
FROM node:22.23.1-alpine3.23@sha256:8516dce0483394d5708d4b2ee6cacb79fb1d617ea4e2787c2120bcca92ce372e AS console-build
WORKDIR /src
COPY console/package.json console/package-lock.json ./
RUN npm ci
COPY console/ ./
RUN npm run build
FROM golang:1.27.1-alpine3.23@sha256:0908ac9b9319e09d7c238aabe914e0395c51d63c4e3d0ae8c554fda9158a5769 AS controller-build
WORKDIR /src/controller
COPY shared/source/ /src/shared/source/
COPY controller/go.mod controller/go.sum ./
RUN go mod download
COPY controller/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/aegisd ./cmd/aegisd && CGO_ENABLED=0 go build -trimpath -o /out/aegisctl ./cmd/aegisctl && CGO_ENABLED=0 go build -trimpath -o /out/fixture-worker ./cmd/fixture-worker && CGO_ENABLED=0 go build -trimpath -o /out/policy-deployer ./cmd/policy-deployer
FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
RUN addgroup -g 10001 aegis && adduser -D -u 10001 -G aegis aegis && mkdir -p /run/scanner /var/lib/aegis /run/verifier /var/log/aegis /run/gateway /run/deployer /var/lib/deployer /data /config && chmod 700 /run/scanner && chown -R 10001:10001 /run/scanner /var/lib/aegis /run/verifier /var/log/aegis /run/gateway /run/deployer /var/lib/deployer /data /config
COPY --from=gateway-build /out/caddy /usr/local/bin/caddy
COPY --from=controller-build /out/ /usr/local/bin/
COPY --from=console-build /src/dist /opt/aegis/console
COPY tools/scanners.lock.json /opt/aegis/scanners.lock.json
USER 10001:10001
ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config
ENTRYPOINT ["aegisd"]
