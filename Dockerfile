# Kernel Release Image
# Distroless Java 25 (LTS) on Debian 13 with no shell. The jar is compiled for
# Java 21 (maven.compiler.release) and runs unchanged on 25.
# The launcher (tacplus-dev/launcher) is the entrypoint: it runs LAUNCH_CMD (java)
# and supervises it. It is the pinned release LAUNCHER_VERSION, downloaded from its
# GitHub release and verified against that release's checksums.txt (the sha256 on
# each ADD below): a mismatch fails the build. To move it, change the version and
# both sha256s together.

ARG LAUNCHER_VERSION=v0.1.0

FROM scratch AS launcher-amd64
ARG LAUNCHER_VERSION
ADD --checksum=sha256:903693ab56879b5a5b54779c3e20efa3ddd5f1269fb0c2274882befb7df69e0f --chmod=755 https://github.com/tacplus-dev/launcher/releases/download/${LAUNCHER_VERSION}/launcher-linux-amd64 /launcher

FROM scratch AS launcher-arm64
ARG LAUNCHER_VERSION
ADD --checksum=sha256:f07933da11e08812afa87d814ecbd187087f20c2af7f62d0c1d356754643ec16 --chmod=755 https://github.com/tacplus-dev/launcher/releases/download/${LAUNCHER_VERSION}/launcher-linux-arm64 /launcher

FROM launcher-${TARGETARCH} AS launcher

# Pre-create /data (config mount point) and /app/data (PVC data dir) with correct
# ownership for the distroless nonroot user (65532).
FROM busybox AS setup
RUN mkdir -p /data /app/data

# The base is pinned by its multi-arch index digest (the image `latest` was on 2026-11-17, Debian 13.7), so the
# image changes base only in a commit: a fixed Debian package reaches it by moving this digest (#66).
FROM gcr.io/distroless/java25-debian13@sha256:6558dff7db91bf89d34254014dec8ff1f0a3e13f48a575d5a51ce01d1597d671

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Jody Scott <jody@thescottsweb.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="tacplus.dev" \
      org.opencontainers.image.title="Kernel" \
      org.opencontainers.image.description="Core kernel service for Schematic control plane"

COPY --from=setup --chown=65532:65532 /data /data
COPY --from=setup --chown=65532:65532 /app/data /app/data
COPY server/target/kernel.jar /app/kernel.jar

COPY --from=launcher /launcher /usr/local/bin/launcher

USER nonroot

# The launcher's health probe is plaintext (launcher v0.1.0): kernel's plaintext
# grpc.health.v1 port is health_probe_port (8444), not its TLS listener (5000).
ENV HEALTH_PORT=8444

ENV LAUNCH_CMD="java -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:InitiatingHeapOccupancyPercent=45 -XX:+UseStringDeduplication -XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:MinRAMPercentage=50.0 -XX:+ExitOnOutOfMemoryError -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp/kernel-heapdump.hprof -Djava.net.preferIPv4Stack=true -Dio.netty.recycler.maxCapacityPerThread=0 -jar /app/kernel.jar"

ENTRYPOINT ["launcher"]
