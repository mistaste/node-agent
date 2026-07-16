FROM alpine:3.22 AS artifact

ARG TARGETARCH=amd64
ARG NODE_AGENT_RELEASE=v0.3.3

# Compile the Xray control-plane once in CI/release tooling instead of on every
# small VPN node.  The immutable, architecture-specific digest keeps the
# download fail-closed even if the release URL is changed or replaced.
RUN apk add --no-cache ca-certificates wget \
    && case "$TARGETARCH" in \
         amd64) expected="5c483842dfd03bb6cd5953b38d42d1ae9bd2bfa9b748ba6c89fbd7b6dacb77ad" ;; \
         arm64) expected="08e11eb1692cf862969b144772b7d1b5910d610712871fb7b57457aa229155bb" ;; \
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
