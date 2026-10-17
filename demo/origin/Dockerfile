FROM golang:1.27.1-alpine3.23@sha256:0908ac9b9319e09d7c238aabe914e0395c51d63c4e3d0ae8c554fda9158a5769 AS build
WORKDIR /src
COPY demo/origin/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/demo .
FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
LABEL org.opencontainers.image.title="Aegis Community demo origin" org.opencontainers.image.vendor="Kynthia AI" org.opencontainers.image.licenses="BUSL-1.1" org.opencontainers.image.source="https://github.com/ks4ai25-a11y/aegis-community"
COPY --from=build /out/demo /usr/local/bin/demo
USER 10001:10001
ENTRYPOINT ["demo"]
