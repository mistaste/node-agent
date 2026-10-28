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
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags="-s -w" -o /transport-bundle-runner ./cmd/transport-bundle-runner \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags="-s -w" -o /account-qos ./cmd/account-qos

FROM golang:1.26.8-alpine3.24@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS caddy-naive
ENV GOPROXY=https://goproxy.cn,direct
COPY ops/patches/forwardproxy-account-qos.patch /patches/account-qos.patch
RUN apk add --no-cache git \
    && git clone https://github.com/klzgrad/forwardproxy /forwardproxy \
    && cd /forwardproxy \
    && git checkout d62c80d3dd2c706b6b87579844d2397bddd18317 \
    && git apply /patches/account-qos.patch \
    && go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.6 \
    && /go/bin/xcaddy build v2.11.4 \
       --with github.com/caddyserver/forwardproxy=/forwardproxy \
       --output /caddy \
    && /caddy version

FROM adguard/core-libs@sha256:79273e6cfee10546af7edbb0122660b9e53e3380742181f5afbe068b212810c4 AS trusttunnel
ARG TARGETARCH
COPY ops/patches/trusttunnel-udp-rejection-v1.1.0.patch /patches/udp-rejection.patch
COPY ops/patches/trusttunnel-live-credentials-v1.1.0.patch /patches/live-credentials.patch
COPY ops/patches/trusttunnel-account-qos-v1.1.0.patch /patches/account-qos.patch
COPY ops/build-trusttunnel-live-credentials.sh /build-endpoint.sh
COPY ops/patches/h2-0.3.27-reclaim-capacity.patch /patches/h2-capacity.patch
COPY ops/prepare-h2-capacity.sh /prepare-h2-capacity.sh
COPY ops/patches/trusttunnel-h2-capacity.lock /patches/endpoint.lock
RUN git clone --depth 1 --branch v1.1.0 https://github.com/TrustTunnel/TrustTunnel.git /trusttunnel-source \
    && cd /trusttunnel-source \
    && test "$(git rev-parse HEAD)" = fab5b8353a19332f935fa30869307d37d4a898d1 \
    && git apply /patches/udp-rejection.patch /patches/live-credentials.patch \
    && git apply /patches/account-qos.patch \
    && sh /prepare-h2-capacity.sh \
    && sh /build-endpoint.sh "$TARGETARCH"

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache ca-certificates docker-cli docker-cli-compose git haproxy iproute2 iptables nftables wireguard-tools
COPY --from=builder /account-qos /usr/local/sbin/guardex-account-qos
COPY --from=builder /node-agent /usr/local/bin/node-agent
COPY --from=builder /topology-agent /usr/local/bin/topology-agent
COPY --from=builder /trusttunnel-runner /usr/local/bin/trusttunnel-runner
COPY --from=builder /transport-bundle-runner /usr/local/bin/transport-bundle-runner
COPY --from=caddy-naive /caddy /usr/bin/caddy
COPY --from=trusttunnel /trusttunnel_endpoint /opt/trusttunnel/trusttunnel_endpoint
EXPOSE 8099
CMD ["node-agent"]
