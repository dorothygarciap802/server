FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WS_HOST=0.0.0.0 \
    WS_PORT=8000 \
    TCP_TARGET_HOST=bntpool.com \
    TCP_TARGET_PORT=3333

WORKDIR /app

RUN python -m pip install --no-cache-dir --only-binary=:all: cryptography==50.0.2 websockets==16.1.1

COPY server.py /app/server.py

# Numeric IDs avoid collisions with accounts already present in the base image.
USER 10001:10001
EXPOSE 8000

CMD ["python", "/app/server.py"]
