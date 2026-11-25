FROM mcr.microsoft.com/devcontainers/java:3-11-bookworm

USER root
COPY --from=maven:3.9.9-eclipse-temurin-11 /usr/share/maven /opt/maven
ENV MAVEN_HOME=/opt/maven
ENV PATH="${MAVEN_HOME}/bin:${PATH}"
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && apt-get clean

USER vscode
