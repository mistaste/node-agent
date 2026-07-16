FROM alpine:3.22 AS artifact

ARG TARGETARCH=amd64
ARG NODE_AGENT_RELEASE=v0.2.3

# Compile the Xray control-plane once in CI/release tooling instead of on every
# small VPN node.  The immutable, architecture-specific digest keeps the
# download fail-closed even if the release URL is changed or replaced.
RUN apk add --no-cache ca-certificates wget \
    && case "$TARGETARCH" in \
         amd64) expected="16dc69684030f082ac79bacd25cef197b34a38f9cd9ef6f73bd4a252c161af70" ;; \
         arm64) expected="53a96f99fc475c668623a1bcbbff1fab3b8ded5d5d0bfe408506d6b24dd2e2f0" ;; \
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
