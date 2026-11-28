# Kernel Release Image
# Distroless Java 25 (LTS) on Debian 13 with no shell. The jar is compiled for
# Java 21 (maven.compiler.release) and runs unchanged on 25.
# The launcher (tacplus-dev/launcher) is the entrypoint: it runs LAUNCH_CMD (java)
# and supervises it. It is the pinned release LAUNCHER_VERSION, downloaded from its
# GitHub release and verified against that release's checksums.txt (the sha256 on
# each ADD below): a mismatch fails the build. To move it, change the version and
# both sha256s together.
#
# Every base image is pinned by its multi-arch index digest (#67), so a release
# builds on exactly the image it was tested on, not on whatever a moving tag
# points at that day. The base's fixes (distroless's Debian packages) reach the
# image only when its digest moves: resolve the tag named beside each FROM to
# its index digest and change it in a commit of its own, e.g.
# `crane digest gcr.io/distroless/java25-debian13:latest`.

ARG LAUNCHER_VERSION=v0.1.0

# Both platforms' launchers, each verified; the image copies its own platform's
# (COPY --from=launcher below). One stage, not a stage per platform picked by
# FROM launcher-${TARGETARCH}: trivy reads a FROM naming a stage by a build arg
# as an untagged image (DS-0001, #67).
FROM scratch AS launcher
ARG LAUNCHER_VERSION
ADD --checksum=sha256:903693ab56879b5a5b54779c3e20efa3ddd5f1269fb0c2274882befb7df69e0f --chmod=755 https://github.com/tacplus-dev/launcher/releases/download/${LAUNCHER_VERSION}/launcher-linux-amd64 /launcher-linux-amd64
ADD --checksum=sha256:f07933da11e08812afa87d814ecbd187087f20c2af7f62d0c1d356754643ec16 --chmod=755 https://github.com/tacplus-dev/launcher/releases/download/${LAUNCHER_VERSION}/launcher-linux-arm64 /launcher-linux-arm64

# Pre-create /data (config mount point) and /app/data (PVC data dir) with correct
# ownership for the distroless nonroot user (65532).
FROM busybox:1.38.0@sha256:a46257e06c82ad85242d0d38077d0a52d9896389ca60a1a59d3463db586e5fa4 AS setup
RUN mkdir -p /data /app/data

# gcr.io/distroless/java25-debian13:latest, resolved 2026-11-25 (Debian 13.8): it
# has no version tags, so it is pinned by its multi-arch index digest alone, and
# the image changes base only in a commit: a fixed Debian package reaches it by
# moving this digest (#66, #67). No HEALTHCHECK: Kubernetes probes the launcher
# (HEALTH_PORT) and ignores Docker's, and distroless has no shell to run one
# (DS-0026, accepted in security-exceptions.yaml).
FROM gcr.io/distroless/java25-debian13@sha256:2b69a4e2c905ec18cdf267f4b3821ac9feaf737dae588a190f918079b380e434

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

ARG TARGETARCH
COPY --from=launcher /launcher-linux-${TARGETARCH} /usr/local/bin/launcher

USER nonroot

# The launcher's health probe is plaintext (launcher v0.1.0): kernel's plaintext
# grpc.health.v1 port is health_probe_port (8444), not its TLS listener (5000).
ENV HEALTH_PORT=8444

ENV LAUNCH_CMD="java -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:InitiatingHeapOccupancyPercent=45 -XX:+UseStringDeduplication -XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:MinRAMPercentage=50.0 -XX:+ExitOnOutOfMemoryError -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp/kernel-heapdump.hprof -Djava.net.preferIPv4Stack=true -Dio.netty.recycler.maxCapacityPerThread=0 -jar /app/kernel.jar"

ENTRYPOINT ["launcher"]
