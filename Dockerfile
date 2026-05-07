# Kernel Release Image
# Layers the kernel jar and kernel binary onto a JRE base.

FROM registry.gitlab.com/secondstarcavalier/schematic/containers/jre/schematic-jre-1-2:latest

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Second Star Cavalier LLC <cloudctlplane@secondstarcavalier.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Second Star Cavalier LLC" \
      org.opencontainers.image.title="Kernel" \
      org.opencontainers.image.description="Core kernel service for Cavalier control plane"

RUN addgroup -S kernel && adduser -S kernel -G kernel

COPY server/target/kernel.jar /app/kernel.jar
COPY kernel /usr/local/bin/kernel
RUN chmod +x /usr/local/bin/kernel \
    && mkdir -p /app/data && chown kernel:kernel /app/data

USER kernel

ENTRYPOINT ["kernel"]
