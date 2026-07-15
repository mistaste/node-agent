FROM alpine:3.22 AS artifact

ARG TARGETARCH=amd64
ARG NODE_AGENT_RELEASE=v0.2.2

# Compile the Xray control-plane once in CI/release tooling instead of on every
# small VPN node.  The immutable, architecture-specific digest keeps the
# download fail-closed even if the release URL is changed or replaced.
RUN apk add --no-cache ca-certificates wget \
    && case "$TARGETARCH" in \
         amd64) expected="a2446d483939734df70a46e329c839cc0a4a942c235ec470386db5de15ea9c09" ;; \
         arm64) expected="95f666b5290e8741255a22eacd3282d7c94880a7d998428ce75a84b663ba216f" ;; \
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
