ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.13-alpine3.21
FROM ${BUILD_FROM}

WORKDIR /app

RUN apk add --no-cache findutils tar
RUN pip3 install --no-cache-dir fastmcp==3.4.2

COPY src /app/src
COPY config.yaml /app/config.yaml
COPY bin/ha /usr/local/bin/ha
RUN chmod +x /usr/local/bin/ha

CMD ["python3", "/app/src/server.py"]
