FROM golang:1.27.1-alpine3.23@sha256:0908ac9b9319e09d7c238aabe914e0395c51d63c4e3d0ae8c554fda9158a5769 AS build
WORKDIR /src
COPY gateway/go.mod gateway/go.sum ./
RUN go mod download
COPY gateway/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/caddy ./cmd/caddy
FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
RUN addgroup -g 10001 aegis && adduser -D -u 10001 -G aegis aegis && mkdir -p /run/gateway /var/log/aegis /data /config /var/lib/aegis && chown -R 10001:10001 /run/gateway /var/log/aegis /data /config /var/lib/aegis
COPY --from=build /out/caddy /usr/local/bin/caddy
USER 10001:10001
ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config
ENTRYPOINT ["caddy"]
