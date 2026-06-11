ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.13-alpine3.21
FROM ${BUILD_FROM}

WORKDIR /app

COPY rootfs /
COPY src /app/src

RUN chmod +x /etc/services.d/ha-admin-mcp/run

CMD ["/etc/services.d/ha-admin-mcp/run"]
