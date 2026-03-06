FROM eclipse-temurin:21-jre

RUN groupadd -r kernel && useradd -r -g kernel kernel

WORKDIR /app

COPY target/kernel-core.jar /app/kernel-core.jar
RUN mkdir -p /app/data && chown kernel:kernel /app/data

USER kernel

ENTRYPOINT ["java", "-jar", "/app/kernel-core.jar"]
