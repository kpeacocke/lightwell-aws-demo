ARG RUNTIME_BASE
FROM ${RUNTIME_BASE}
WORKDIR /app
COPY app.jar /app/app.jar
COPY lib/ /app/lib/
USER 10001:10001
ENTRYPOINT ["java", "-cp", "/app/app.jar:/app/lib/*", "com.parasol.paymentgateway.App"]
