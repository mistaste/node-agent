FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS artifact

ARG TARGETARCH=amd64
ARG NODE_AGENT_RELEASE=v0.3.4

# Compile the Xray control-plane once in CI/release tooling instead of on every
# small VPN node.  The immutable, architecture-specific digest keeps the
# download fail-closed even if the release URL is changed or replaced.
RUN apk add --no-cache ca-certificates wget \
    && case "$TARGETARCH" in \
         amd64) expected="0cd9b7e3ea79ad7edfa53477ed3ab687671324b01bfeec82107092b82743082d" ;; \
         arm64) expected="fdad63a9226bc03ebc49a46c528cdabb87a898d295332e3dfc1baf58a7db29af" ;; \
         *) echo "unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && wget -q -O /node-agent "https://github.com/mistaste/node-agent/releases/download/${NODE_AGENT_RELEASE}/guardex-node-agent-${NODE_AGENT_RELEASE}-linux-${TARGETARCH}" \
    && echo "$expected  /node-agent" | sha256sum -c - \
    && chmod 0755 /node-agent

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache ca-certificates docker-cli docker-cli-compose git
COPY --from=artifact /node-agent /usr/local/bin/node-agent
EXPOSE 8099
CMD ["node-agent"]
