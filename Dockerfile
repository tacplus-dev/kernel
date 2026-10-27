# Kernel Release Image
# Distroless Java 25 (LTS) on Debian 13 with no shell. The jar is compiled for
# Java 21 (maven.compiler.release) and runs unchanged on 25.
# The launcher binary (copied from the CI context) reads LAUNCH_CMD and execs java.

# Pre-create /data (config mount point) and /app/data (PVC data dir) with correct
# ownership for the distroless nonroot user (65532).
FROM busybox AS setup
RUN mkdir -p /data /app/data

FROM gcr.io/distroless/java25-debian13

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
COPY launcher-linux-${TARGETARCH} /usr/local/bin/launcher

USER nonroot

ENV LAUNCH_CMD="java -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:InitiatingHeapOccupancyPercent=45 -XX:+UseStringDeduplication -XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -XX:MinRAMPercentage=50.0 -XX:+ExitOnOutOfMemoryError -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp/kernel-heapdump.hprof -Djava.net.preferIPv4Stack=true -Dio.netty.recycler.maxCapacityPerThread=0 -jar /app/kernel.jar"

ENTRYPOINT ["launcher"]
