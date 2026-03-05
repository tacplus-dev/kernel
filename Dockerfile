FROM eclipse-temurin:21-jre

RUN groupadd -r elvis && useradd -r -g elvis elvis

WORKDIR /app

COPY target/elvis.jar /app/elvis.jar
COPY elvis /app/elvis
RUN chmod +x /app/elvis && mkdir -p /app/data && chown elvis:elvis /app/data

USER elvis

ENTRYPOINT ["/app/elvis"]
