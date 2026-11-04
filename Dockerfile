FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WS_HOST=0.0.0.0 \
    WS_PORT=8000 \
    TCP_TARGET_HOST=bntpool.com \
    TCP_TARGET_PORT=3333

WORKDIR /app

COPY proxy/requirements.txt /app/proxy/requirements.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: -r /app/proxy/requirements.txt \
    && useradd --create-home --uid 10001 proxy

# Only Python helpers are imported; the gateway never starts a hashing engine.
COPY src/ /app/bnt_cpu_miner/
COPY proxy/server.py /app/proxy/server.py
COPY LICENSE /app/LICENSE

ENV PYTHONPATH=/app
USER proxy
EXPOSE 8000

CMD ["python", "/app/proxy/server.py"]
