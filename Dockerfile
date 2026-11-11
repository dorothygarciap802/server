FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WS_HOST=0.0.0.0 \
    WS_PORT=8000 \
    PROXY_BIN=/app/proxy \
    PROXY_LISTEN=127.0.0.1:3344 \
    PROXY_POOL_URL=stratum+tcp://bntpool.com:3333 \
    PROXY_WORKER=farm-1

WORKDIR /app

RUN python -m pip install --no-cache-dir --only-binary=:all: cryptography==50.0.2 websockets==16.1.1

COPY --chmod=755 proxy /app/proxy
COPY server.py /app/server.py

RUN mkdir -p /app/seine-data && chown 10001:10001 /app/seine-data

# Numeric IDs avoid collisions with accounts already present in the base image.

USER 10001:10001
EXPOSE 8000

CMD ["python", "/app/server.py"]