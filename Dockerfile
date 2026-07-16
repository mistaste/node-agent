FROM alpine:3.22 AS artifact

ARG TARGETARCH=amd64
ARG NODE_AGENT_RELEASE=v0.3.2

# Compile the Xray control-plane once in CI/release tooling instead of on every
# small VPN node.  The immutable, architecture-specific digest keeps the
# download fail-closed even if the release URL is changed or replaced.
RUN apk add --no-cache ca-certificates wget \
    && case "$TARGETARCH" in \
         amd64) expected="0e84a8bda0940a372ae9cde44a135a8523718c7fe6a0bd93225e8abffbbe9469" ;; \
         arm64) expected="e60f07402cdc6c06bb43bbb61cf49265b522994dbb4391901d68ee2e4a20aa7d" ;; \
         *) echo "unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && wget -q -O /node-agent "https://github.com/mistaste/node-agent/releases/download/${NODE_AGENT_RELEASE}/guardex-node-agent-${NODE_AGENT_RELEASE}-linux-${TARGETARCH}" \
    && echo "$expected  /node-agent" | sha256sum -c - \
    && chmod 0755 /node-agent

FROM alpine:3.22
RUN apk add --no-cache ca-certificates docker-cli docker-cli-compose git
COPY --from=artifact /node-agent /usr/local/bin/node-agent
EXPOSE 8099
CMD ["node-agent"]
