FROM eclipse-temurin:21-jre

RUN groupadd -r kernel && useradd -r -g kernel kernel

WORKDIR /app

COPY server/target/kernel.jar /app/kernel.jar
COPY kernel /usr/bin/kernel
RUN chmod +x /usr/bin/kernel && \
    mkdir -p /app/data && chown kernel:kernel /app/data

USER kernel

ENTRYPOINT ["kernel"]
