FROM mcr.microsoft.com/devcontainers/java:3-11-bookworm

USER 0
COPY --from=maven:3.9.9-eclipse-temurin-11 /usr/share/maven /opt/maven
COPY --from=hadolint/hadolint:v2.15.1-debian /bin/hadolint /usr/local/bin/hadolint
ENV MAVEN_HOME=/opt/maven
ENV PATH="${MAVEN_HOME}/bin:${PATH}"
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        'nodejs=18.*' 'npm=9.*' \
    && npm install --global markdownlint-cli2@0.17.2 \
    && npm cache clean --force \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists

# Keep the named user for devcontainer UID remapping.
# hadolint ignore=DL3066
USER vscode
