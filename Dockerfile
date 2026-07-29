FROM golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags="-s -w" -o /node-agent .

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS trusttunnel
ARG TARGETARCH=amd64
RUN apk add --no-cache ca-certificates wget tar \
    && case "$TARGETARCH" in \
         amd64) tt_arch="x86_64"; tt_sha="48802662bc745aed60207c6ed6465d9fed428b1e53532045689d89bcad19bdd9" ;; \
         arm64) tt_arch="aarch64"; tt_sha="8b0d13d11f607c1da18be921096de3f85af67520b305aad425c74dd4f6775697" ;; \
         *) echo "unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && tt_archive="trusttunnel-v1.0.33-linux-${tt_arch}.tar.gz" \
    && wget -q -O "/${tt_archive}" "https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.0.33/${tt_archive}" \
    && echo "$tt_sha  /${tt_archive}" | sha256sum -c - \
    && mkdir -p /trusttunnel-unpack \
    && tar -xzf "/${tt_archive}" -C /trusttunnel-unpack \
    && find /trusttunnel-unpack -type f -name trusttunnel_endpoint -perm -u+x -exec cp '{}' /trusttunnel_endpoint \; \
    && test -x /trusttunnel_endpoint

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache ca-certificates docker-cli docker-cli-compose git
COPY --from=builder /node-agent /usr/local/bin/node-agent
COPY --from=trusttunnel /trusttunnel_endpoint /opt/trusttunnel/trusttunnel_endpoint
EXPOSE 8099
CMD ["node-agent"]
