FROM golang:1.26.8-alpine3.24@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS builder
ENV GOPROXY=https://goproxy.cn,direct
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags="-s -w" -o /node-agent . \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags="-s -w" -o /topology-agent ./cmd/topology-agent \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags="-s -w" -o /trusttunnel-runner ./cmd/trusttunnel-runner \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags="-s -w" -o /transport-bundle-runner ./cmd/transport-bundle-runner

FROM golang:1.26.8-alpine3.24@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS caddy-naive
ENV GOPROXY=https://goproxy.cn,direct
RUN apk add --no-cache git \
    && go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.6 \
    && /go/bin/xcaddy build v2.11.4 \
       --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@d62c80d3dd2c706b6b87579844d2397bddd18317 \
       --output /caddy \
    && /caddy version

FROM adguard/core-libs@sha256:79273e6cfee10546af7edbb0122660b9e53e3380742181f5afbe068b212810c4 AS trusttunnel
ARG TARGETARCH
COPY ops/patches/trusttunnel-udp-rejection-v1.1.0.patch /patches/udp-rejection.patch
COPY ops/patches/trusttunnel-live-credentials-v1.1.0.patch /patches/live-credentials.patch
COPY ops/build-trusttunnel-live-credentials.sh /build-endpoint.sh
RUN git clone --depth 1 --branch v1.1.0 https://github.com/TrustTunnel/TrustTunnel.git /trusttunnel-source \
    && cd /trusttunnel-source \
    && test "$(git rev-parse HEAD)" = fab5b8353a19332f935fa30869307d37d4a898d1 \
    && git apply /patches/udp-rejection.patch /patches/live-credentials.patch \
    && sh /build-endpoint.sh "$TARGETARCH"

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache ca-certificates docker-cli docker-cli-compose git haproxy iproute2 iptables nftables wireguard-tools
COPY --from=builder /node-agent /usr/local/bin/node-agent
COPY --from=builder /topology-agent /usr/local/bin/topology-agent
COPY --from=builder /trusttunnel-runner /usr/local/bin/trusttunnel-runner
COPY --from=builder /transport-bundle-runner /usr/local/bin/transport-bundle-runner
COPY --from=caddy-naive /caddy /usr/bin/caddy
COPY --from=trusttunnel /trusttunnel_endpoint /opt/trusttunnel/trusttunnel_endpoint
EXPOSE 8099
CMD ["node-agent"]
