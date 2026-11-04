# BNT WebSocket gateway

## Docker

Build from the `bnt-cpu-miner` repository root:

```sh
docker build -f proxy/Dockerfile -t bnt-proxy .
docker run -d --name bnt-proxy --restart unless-stopped \
  -p 8000:8000 \
  -e PROXY_PRIVATE_KEY=YOUR_32_BYTE_X25519_PRIVATE_KEY_HEX \
  bnt-proxy
docker logs -f bnt-proxy
```

The gateway listens on `0.0.0.0:8000` inside the container. Miners connect to
`ws://YOUR_PROXY_HOST:8000` (or the `wss://` URL of your TLS reverse proxy).
The image needs no Rust compiler or native mining library. Keep
`PROXY_PRIVATE_KEY` fixed across restarts; omit it to generate a temporary key.

## Run without Docker

Install the built `bnt-cpu-miner` wheel on the proxy host so the gateway can import
its crypto and protocol helpers. The gateway does not create a native CPU engine.

```sh
python -m pip install /path/to/bnt_cpu_miner-*.whl
export WS_HOST=0.0.0.0
export WS_PORT=8000
export PROXY_PRIVATE_KEY=YOUR_32_BYTE_X25519_PRIVATE_KEY_HEX
python proxy/server.py
```

The default upstream is `stratum+tcp://bntpool.com:3333`. Override
`TCP_TARGET_HOST` and `TCP_TARGET_PORT` only when using another pool; the host
value is a hostname without the `stratum+tcp://` prefix. Use a **plain TCP
Blocknet Stratum** endpoint. Put a TLS reverse proxy in front of the gateway for a public `wss://`
endpoint. Miners configure this URL through STATEAA. The public key is logged at
startup. If `PROXY_PRIVATE_KEY` is omitted, a temporary key is generated for that
process. The miner exposes no CLI parameters.

The gateway translates encrypted `worker.register`/`worker.solution`/
`worker.refill` messages into pool `login`/`submit`/`refill` requests. It forwards
jobs, accepted/rejected share results and pool capabilities. It preserves `u64`
nonce integers, keeps early jobs until login is accepted and waits for pending
share acknowledgements before sending a requested refill. A refused refill closes
the session so the miner can log in for fresh work.

The password field is required by the E2E registration format but Blocknet's
reference login protocol uses `address`, `worker`, `protocol_version` and
`capabilities`; it does not transmit a pool password. This gateway targets BNT,
not the PRL/Kryptex pool configured by the original JavaScript proxy.

An optional `memo` in worker registration is validated and forwarded as
`payout_memo` in the pool login. Before sending `worker.ready` or any buffered job,
the gateway requires `payout_memo_v1` and an exact `payout_account` acknowledgement
matching the reference SHA3 account-identity contract. It forwards that identity
to the miner for a second check. Pools without that acknowledgement are refused
when a memo is configured. Longhorn address-encoded memos are not enabled by this
plain-TCP gateway.
