ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.13-alpine3.24-2026.06.1
FROM ${BUILD_FROM}

WORKDIR /app

RUN apk add --no-cache findutils tar
RUN pip3 install --no-cache-dir fastmcp==3.4.2

COPY src /app/src
COPY config.yaml /app/config.yaml
COPY icon.png /app/icon.png
COPY icon.svg /app/icon.svg
COPY logo.png /app/logo.png
COPY logo.svg /app/logo.svg
COPY bin/ha /usr/local/bin/ha
RUN chmod +x /usr/local/bin/ha

CMD ["python3", "/app/src/server.py"]
