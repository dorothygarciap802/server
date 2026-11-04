FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WS_HOST=0.0.0.0 \
    WS_PORT=8000 \
    TCP_TARGET_HOST=bntpool.com \
    TCP_TARGET_PORT=3333

WORKDIR /app

RUN python -m pip install --no-cache-dir --only-binary=:all: cryptography==50.0.2 websockets==16.1.1 \
    && useradd --create-home --uid 10001 proxy

COPY server.py /app/server.py

USER proxy
EXPOSE 8000

CMD ["python", "/app/server.py"]
