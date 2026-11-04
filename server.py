#!/usr/bin/env python3
"""BNT gateway: existing proxy E2E wire format, native Blocknet pool protocol.
Install bnt-cpu-miner first. Python preserves all unsigned 64-bit nonce values.
"""
import asyncio
import json
import logging
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from websockets.asyncio.server import serve

from bnt_cpu_miner.crypto import Session
from bnt_cpu_miner.miner import Job, integer
from bnt_cpu_miner.payout import MEMO_CAPABILITY, account_id, validate_destination

log = logging.getLogger("bnt-proxy")


async def gateway(ws, *, private, pool_host, pool_port):
    writer = None
    tasks = []
    try:
        public_hex = await asyncio.wait_for(ws.recv(), 15)
        if not isinstance(public_hex, str) or len(public_hex) != 64:
            raise ValueError("invalid handshake")
        session = Session(private.exchange(X25519PublicKey.from_public_bytes(
            bytes.fromhex(public_hex))), server=True)
        await ws.send(private.public_key().public_bytes_raw().hex())
        send_lock = asyncio.Lock()

        async def send(method, params):
            async with send_lock:
                await ws.send(session.encrypt({"method": method, "params": params}))

        registration = session.decrypt(await asyncio.wait_for(ws.recv(), 15))
        if registration.get("method") != "worker.register":
            raise ValueError("worker.register required")
        params = registration["params"]
        if not all(isinstance(params.get(k), str) and params[k] for k in ("wallet", "worker", "password")):
            raise ValueError("invalid registration")
        memo = params.get('memo')
        validate_destination(params['wallet'], memo)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            pool_host, pool_port, limit=1024 * 1024), 15)

        async def pool_send(value):
            writer.write((json.dumps(value, separators=(",", ":")) + "\n").encode())
            await writer.drain()

        login = {
            "address": params["wallet"], "worker": params["worker"], "protocol_version": 2,
            "capabilities": ["submit_claimed_hash", "nonce_refill_v1", MEMO_CAPABILITY],
        }
        if memo is not None:
            login['payout_memo'] = memo
        await pool_send({"id": 1, "method": "login", "params": login})
        authorized = False
        capabilities = set()
        early_jobs = []
        jobs = {}
        pending = {}
        request_id = 100
        refill_job = None
        refill_request = None
        seen = set()

        async def publish(job):
            parsed = Job.parse(job)
            jobs[parsed.job_id] = parsed.params
            await send("worker.dataset", parsed.params)

        async def maybe_refill():
            nonlocal request_id, refill_request, refill_job
            if refill_job is not None and not pending and refill_request is None:
                request_id += 1
                refill_request = request_id
                await pool_send({"id": request_id, "method": "refill", "params": {"job_id": refill_job}})

        async def from_pool():
            nonlocal authorized, capabilities, refill_request, refill_job
            while True:
                line = await reader.readline()
                if not line:
                    return
                message = json.loads(line)
                method, identity = message.get("method"), message.get("id")
                if method == "job":
                    refill_job = None
                    if authorized:
                        await publish(message["params"])
                    else:
                        if len(early_jobs) >= 32:
                            raise ValueError("too many jobs before login")
                        early_jobs.append(message["params"])
                elif identity == 1:
                    if str(message.get("status", "")).lower() != "ok" or message.get("error"):
                        await send("worker.error", {"message": "BNT pool login rejected", "retry_after": 30})
                        return
                    result = message.get('result') or {}
                    capabilities = set(result.get("capabilities", []))
                    payout_account = result.get('payout_account')
                    if memo is not None and (MEMO_CAPABILITY not in capabilities
                            or payout_account != account_id(params['wallet'], memo)):
                        await send('worker.error', {'message': 'pool did not acknowledge the payout memo',
                                                    'fatal': True})
                        return
                    authorized = True
                    await send("worker.ready", {"type": "bnt", "capabilities": sorted(capabilities),
                                                'payout_account': payout_account})
                    for job in early_jobs:
                        await publish(job)
                    early_jobs.clear()
                elif identity == refill_request and refill_request is not None:
                    refill_request = None
                    if message.get("error") or not isinstance(message.get("result"), dict):
                        # The client reconnects for a new login/range on refusal.
                        await send("worker.error", {"message": "nonce refill refused", "retry_after": 5})
                        return
                    refill_job = None
                    await publish(message["result"])
                elif identity in pending:
                    solution = pending.pop(identity)
                    result = message.get("result") or {}
                    accepted = (result.get("accepted", str(message.get("status", "")).lower() == "ok")
                                if isinstance(result, dict) else False)
                    accepted = bool(accepted) and not message.get("error")
                    await send("worker.validation_result", {"job_id": solution["job_id"],
                               "nonce": solution["nonce"], "accepted": accepted,
                               "error": message.get("error") if not accepted else None})
                    await maybe_refill()

        async def from_worker():
            nonlocal request_id, refill_job
            async for frame in ws:
                message = session.decrypt(frame)
                method, value = message.get("method"), message.get("params", {})
                if not authorized:
                    raise ValueError("worker not ready")
                if method == "worker.solution":
                    job = jobs.get(value.get("job_id"))
                    nonce = integer(value.get("nonce"), "nonce")
                    if job is None or not job["nonce_start"] <= nonce <= job["nonce_end"]:
                        raise ValueError("unknown job or nonce outside assigned range")
                    key = (value["job_id"], nonce)
                    if key in seen:
                        raise ValueError("duplicate solution")
                    seen.add(key)
                    request_id += 1
                    solution = {"job_id": value["job_id"], "nonce": nonce,
                                "worker": params["worker"], "backend": "cpu", "miner_version": "0.1.0"}
                    if "submit_claimed_hash" in capabilities and value.get("hash") is not None:
                        if len(bytes.fromhex(value["hash"])) != 32:
                            raise ValueError("invalid claimed hash")
                        solution["claimed_hash"] = value["hash"]
                    pending[request_id] = solution
                    await pool_send({"id": request_id, "method": "submit", "params": solution})
                elif method == "worker.refill":
                    if "nonce_refill_v1" not in capabilities or value.get("job_id") not in jobs:
                        raise ValueError("invalid refill")
                    refill_job = value["job_id"]
                    await maybe_refill()
                else:
                    raise ValueError(f"unsupported worker method: {method}")

        tasks = [asyncio.create_task(from_pool()), asyncio.create_task(from_worker())]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except Exception as error:
        log.warning("Session ended: %s", error)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await ws.close()


async def main():
    private_hex = os.environ.get("PROXY_PRIVATE_KEY")
    private = (X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
               if private_hex else X25519PrivateKey.generate())
    host, port = os.environ.get("WS_HOST", "0.0.0.0"), int(os.environ.get("WS_PORT", "8000"))
    pool_host = os.environ.get("TCP_TARGET_HOST", "bntpool.com")
    pool_port = int(os.environ.get("TCP_TARGET_PORT", "3333"))
    log.info("Proxy public key: %s", private.public_key().public_bytes_raw().hex())

    async def handler(ws):
        await gateway(ws, private=private, pool_host=pool_host, pool_port=pool_port)

    async with serve(handler, host, port, max_size=1024 * 1024, ping_interval=20, ping_timeout=20):
        log.info("ws://%s:%d -> stratum+tcp://%s:%d", host, port, pool_host, pool_port)
        await asyncio.Future()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
