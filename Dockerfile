FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS build
WORKDIR /src
COPY go.mod go.sum ./
# Optional organization CA is build-only, supplied through a BuildKit secret.
RUN --mount=type=secret,id=build_ca \
    if [ -f /run/secrets/build_ca ]; then \
      SSL_CERT_FILE=/run/secrets/build_ca go mod download && go mod verify; \
    else go mod download && go mod verify; fi
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /tool-gateway ./cmd/gateway \
    && mkdir -p /empty-data /empty-tmp && chmod 1777 /empty-tmp

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /tool-gateway /usr/local/bin/tool-gateway
COPY --from=build --chown=65532:65532 /empty-data /data
COPY --from=build /empty-tmp /tmp
USER 65532:65532
EXPOSE 8844
ENTRYPOINT ["/usr/local/bin/tool-gateway"]
CMD ["serve", "--policy", "/etc/tool-gateway/policy.json"]
