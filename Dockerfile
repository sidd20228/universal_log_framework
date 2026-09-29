FROM docker.io/library/golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build

WORKDIR /src

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG TARGETOS=linux
ARG TARGETARCH

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY migrations/ ./migrations/

RUN test -n "${TARGETARCH}" && \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -buildvcs=false -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o /out/ulpf ./cmd/ulpf && \
    install -d -m 0700 \
      /runtime/var/lib/ulpf/raw \
      /runtime/var/lib/ulpf/state \
      /runtime/var/lib/ulpf/bundles \
      /runtime/var/lib/ulpf/tmp

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=1970-01-01T00:00:00Z

LABEL org.opencontainers.image.title="ULPF" \
      org.opencontainers.image.description="Universal Log Processing Framework" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/sidd20228/universal_log_framework"

COPY --from=build --chown=65532:65532 --chmod=0555 /out/ulpf /usr/local/bin/ulpf
COPY --from=build --chown=65532:65532 /runtime/ /
COPY --chown=65532:65532 bundles/ /usr/share/ulpf/bundles/

ENV HOME=/var/lib/ulpf \
    TMPDIR=/var/lib/ulpf/tmp

WORKDIR /var/lib/ulpf
USER 65532:65532

STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/ulpf", "version"]

ENTRYPOINT ["/usr/local/bin/ulpf"]
CMD ["help"]
