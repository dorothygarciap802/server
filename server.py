#!/usr/bin/env python3
"""BNT gateway: existing proxy E2E wire format, native Blocknet pool protocol.
Standalone server. Python preserves all unsigned 64-bit nonce values.
Spawns ./proxy first, waits for its TCP port, then points the gateway at it.
"""
import asyncio
import base64
from collections import deque
from dataclasses import dataclass
import hashlib
import hmac
import json
import logging
import os
import signal
import time
import unicodedata
from urllib.parse import parse_qs, urlsplit
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosedOK

# Keep this file standalone; these helpers match the miner's wire protocol.
MEMO_CAPABILITY = 'payout_memo_v1'
KNOWN_EXCHANGE = 'HH7z6LUoR17owk79Wn4FR8pcG6ntgiURNZxHuuQqA4Sw5iojRc8XZytt5oZqDyUhNUvfbRn5bd8jUPE8MQ8HkDNL3KbFU'
MAX_NONCE = 2**64 - 1


def validate_memo(memo):
    if not isinstance(memo, str) or not 1 <= len(memo.encode('utf-8')) <= 124:
        raise ValueError('memo must contain 1..124 UTF-8 bytes')
    if any(unicodedata.category(character) == 'Cc' for character in memo):
        raise ValueError('memo must not contain control characters')
    return memo


def account_id(wallet, memo=None):
    wallet = wallet.strip()
    if memo is None:
        return wallet
    validate_memo(memo)
    address = wallet.encode('utf-8')
    digest = hashlib.sha3_256(b'blocknet_pool_payout_memo_v1\0'
                             + len(address).to_bytes(8, 'big') + address + memo.encode('utf-8'))
    return 'memo:' + digest.hexdigest()


def validate_destination(wallet, memo=None):
    if not isinstance(wallet, str) or not wallet.strip():
        raise ValueError('wallet is required')
    if memo is not None:
        validate_memo(memo)
    if wallet.strip() == KNOWN_EXCHANGE and memo is None:
        raise ValueError('this exchange address requires a payout memo')


def integer(value, field):
    if type(value) is not int or not 0 <= value <= MAX_NONCE:
        raise ValueError(f'{field} must be an unsigned 64-bit integer')
    return value


@dataclass(frozen=True)
class Job:
    params: dict

    @property
    def job_id(self):
        return self.params['job_id']

    @classmethod
    def parse(cls, params):
        if not isinstance(params, dict):
            raise ValueError('BNT jobs require an object, not a PRL dataset/array')
        if not isinstance(params.get('job_id'), str) or not params['job_id']:
            raise ValueError('invalid job_id')
        header = bytes.fromhex(params['header_base'])
        target = bytes.fromhex(params['target'])
        height = integer(params['height'], 'height')
        start = integer(params['nonce_start'], 'nonce_start')
        end = integer(params['nonce_end'], 'nonce_end')
        if not 8 <= len(header) <= 4096 or len(target) != 32 or end < start:
            raise ValueError('invalid BNT header, target or nonce range')
        if height >= 103_680:
            raise ValueError('Faraday PoW parameters are provisional; this build refuses that height')
        return cls(dict(params))


class Session:
    def __init__(self, secret, *, server=False):
        def key(direction):
            return AESGCM(HKDF(algorithm=hashes.SHA256(), length=32,
                              salt=b'csd-pool-e2e-v1',
                              info=b'aes-256-gcm-key-' + direction).derive(secret))
        self.tx = key(b's2c' if server else b'c2s')
        self.rx = key(b'c2s' if server else b's2c')
        self.counter = 0
        self.last_rx = 0

    def encrypt(self, message):
        self.counter += 1
        nonce = b'CSD!' + self.counter.to_bytes(8, 'big')
        plain = json.dumps(message, separators=(',', ':')).encode()
        return (b'\x0c' + nonce + self.tx.encrypt(nonce, plain, None)).hex()

    def decrypt(self, text):
        if not isinstance(text, str):
            raise ValueError('expected hexadecimal text frame')
        wire = bytes.fromhex(text)
        if len(wire) < 29 or wire[0] != 12 or wire[1:5] != b'CSD!':
            raise ValueError('invalid E2E frame')
        counter = int.from_bytes(wire[5:13], 'big')
        if counter <= self.last_rx:
            raise ValueError('replayed E2E frame')
        plain = self.rx.decrypt(wire[1:13], wire[13:], None)
        self.last_rx = counter
        message = json.loads(plain)
        if not isinstance(message, dict):
            raise ValueError('expected JSON object')
        return message

log = logging.getLogger("bnt-proxy")

DASHBOARD = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BNT · Proxy overview</title><style>
:root{color-scheme:dark;font:14px system-ui,sans-serif;background:#0b0d12;color:#dce1ed}*{box-sizing:border-box}body{margin:0}header{background:#11151d;border-bottom:1px solid #252c39;padding:18px 28px;display:flex;align-items:center;justify-content:space-between;gap:15px}.brand{font-size:19px;font-weight:700}.brand b{color:#ff9830;margin-right:12px}header small,.muted{color:#8290a8}main{max-width:1500px;margin:auto;padding:26px}h1{font-size:25px;margin:0 0 8px}h2{font-size:14px;font-weight:600;margin:0 0 20px}.toolbar{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}.pill{padding:6px 11px;border:1px solid #285746;border-radius:5px;color:#73dfa8;font-size:12px}.pill.bad{color:#ff8a8a;border-color:#663636}.cards{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:16px}.panel,.card{background:#121720;border:1px solid #252d3c;border-radius:7px;padding:20px}.card span{display:block;color:#91a0b8;font-size:12px}.value{font-size:30px;font-weight:600;line-height:1.6;font-variant-numeric:tabular-nums}.green{color:#72dba1}.red{color:#ff7c83}.orange{color:#ffac54}.charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}.chart{width:100%;height:170px;display:block;background:repeating-linear-gradient(to top,transparent,transparent 41px,#242c3a 42px)}.legend{font-size:12px;color:#91a0b8;display:flex;justify-content:space-between;margin-top:12px}.section{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:16px}.section h2{margin:0}input,select{background:#0d1119;color:#cfd8e8;border:1px solid #303b4d;border-radius:4px;padding:8px;max-width:100%}.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;white-space:nowrap;font-size:12px;text-align:left}th{font-weight:500;color:#8998b0;padding:12px 10px;border-bottom:1px solid #30394a}td{padding:13px 10px;border-bottom:1px solid #202735}td:first-child{font-family:monospace;color:#a9bad4}.state{border-radius:4px;padding:4px 7px;background:#202a38;color:#aebed7}.state.live{background:#16392c;color:#7adea8}.events{margin-top:16px}.event{display:flex;gap:20px;padding:10px 0;border-bottom:1px solid #202735;font-size:12px;overflow-wrap:anywhere}.event time{color:#8290a8;min-width:70px}.event code{color:#ffac54;min-width:92px}.empty{color:#8290a8;padding:25px;text-align:center}footer{color:#75839b;font-size:12px;margin-top:18px}.notice{font-size:12px;color:#8290a8;margin:14px 0 0}
@media(max-width:1000px){.cards{grid-template-columns:repeat(3,1fr)}}@media(max-width:650px){main{padding:14px}header{padding:16px}.cards{grid-template-columns:repeat(2,1fr)}.charts{grid-template-columns:1fr}.toolbar,.section{align-items:flex-start;flex-direction:column}.event{gap:10px;flex-wrap:wrap}}
</style></head><body><header><div class="brand"><b>◈</b>BNT <small>/ Proxy observability</small></div><span id="health" class="pill">Connecting…</span></header>
<main><div class="toolbar"><div><h1>Proxy overview</h1><span class="muted" id="upstream">Waiting for telemetry</span></div><span class="muted" id="updated">Live · every 2 seconds</span></div>
<div class="cards">
<div class="card"><span>Active connections</span><div class="value" id="active">—</div></div>
<div class="card"><span>Pool authorized</span><div class="value green" id="authorized">—</div></div>
<div class="card"><span>Accepted shares</span><div class="value green" id="accepted">—</div></div>
<div class="card"><span>Rejected shares</span><div class="value red" id="rejected">—</div></div>
<div class="card"><span>Pending shares</span><div class="value orange" id="pending">—</div></div>
<div class="card"><span>Session errors</span><div class="value" id="errors">—</div></div></div>
<div class="charts"><div class="panel"><h2>Active connections</h2><svg id="connectionsChart" class="chart" viewBox="0 0 600 170" preserveAspectRatio="none" aria-label="Active connections over the last six minutes"></svg><div class="legend"><span>Last 6 minutes · 2s samples</span><span id="connectionsScale"></span></div></div>
<div class="panel"><h2>Share throughput · shares / minute</h2><svg id="sharesChart" class="chart" viewBox="0 0 600 170" preserveAspectRatio="none" aria-label="Accepted and rejected shares per minute"></svg><div class="legend"><span><span class="green">● Accepted</span> &nbsp; <span class="red">● Rejected</span></span><span id="sharesScale"></span></div></div></div>
<div class="panel"><div class="section"><h2>Connections <span class="muted" id="sessionCount"></span></h2><div><select id="filter" aria-label="Connection filter"><option value="active">Active</option><option value="all">Active + recent closed</option></select> <input id="search" placeholder="Search worker or session" aria-label="Search connections"></div></div><div class="tablewrap"><table><thead><tr><th>Session</th><th>Worker</th><th>Status</th><th>Duration</th><th>Jobs</th><th>Accepted</th><th>Rejected</th><th>Pending</th><th>Pool ACK</th><th>Last activity</th><th>Last error</th></tr></thead><tbody id="rows"></tbody></table></div><p class="notice">Pool ACK is submission-to-response latency. Hashrate is unavailable: miners do not send hash telemetry. Recent history is kept in memory and resets on restart.</p></div>
<div class="panel events"><h2>Session activity</h2><div id="events"><div class="empty">No events yet</div></div></div><footer id="summary"></footer></main>
<script>
const el=id=>document.getElementById(id),num=x=>Number(x).toLocaleString(),duration=x=>{x=Math.max(0,Math.floor(x));return x<60?x+'s':x<3600?Math.floor(x/60)+'m '+x%60+'s':Math.floor(x/3600)+'h '+Math.floor(x%3600/60)+'m'};
let latest=null;
function chart(id,series,colors,scaleId){const svg=el(id);svg.replaceChildren();const max=Math.max(1,...series.flat());series.forEach((values,index)=>{if(!values.length)return;const line=document.createElementNS('http://www.w3.org/2000/svg','polyline');line.setAttribute('points',values.map((v,i)=>`${i*600/Math.max(1,values.length-1)},${160-v/max*150}`).join(' '));line.setAttribute('fill','none');line.setAttribute('stroke',colors[index]);line.setAttribute('stroke-width','2');line.setAttribute('vector-effect','non-scaling-stroke');svg.append(line)});el(scaleId).textContent='Scale 0–'+Math.ceil(max)}
function cell(row,text,cls){const td=document.createElement('td');td.textContent=text;if(cls)td.className=cls;row.append(td);return td}
function renderRows(){if(!latest)return;const query=el('search').value.toLowerCase(),rows=latest.sessions.filter(s=>(el('filter').value==='all'||s.status!=='closed')&&(s.worker+' '+s.id).toLowerCase().includes(query));el('rows').replaceChildren();el('sessionCount').textContent='· '+rows.length;for(const s of rows){const tr=document.createElement('tr');cell(tr,s.id);cell(tr,s.worker);const state=cell(tr,'');const badge=document.createElement('span');badge.className='state'+(s.status==='mining'?' live':'');badge.textContent=s.status;state.append(badge);cell(tr,duration((s.closed_at||latest.time)-s.connected_at));cell(tr,num(s.jobs));cell(tr,num(s.accepted),'green');cell(tr,num(s.rejected),'red');cell(tr,num(s.pending));cell(tr,s.latency_ms===null?'—':s.latency_ms+' ms');cell(tr,duration(latest.time-s.last_activity)+' ago');cell(tr,s.error||'—');el('rows').append(tr)}if(!rows.length){const tr=document.createElement('tr');const td=cell(tr,'No matching connections','empty');td.colSpan=11;el('rows').append(tr)}}
function render(d){latest=d;el('health').className='pill';el('health').textContent='● Proxy running';el('upstream').textContent='Upstream '+d.upstream+' · Uptime '+duration(d.uptime_seconds);for(const key of ['active','authorized','pending'])el(key).textContent=num(d[key]);for(const key of ['accepted','rejected','errors'])el(key).textContent=num(d.totals[key]);el('updated').textContent='Updated '+new Date(d.time*1000).toLocaleTimeString();chart('connectionsChart',[d.history.map(x=>x.active)],['#ffac54'],'connectionsScale');const rate=key=>d.history.slice(1).map((x,i)=>Math.max(0,(x[key]-d.history[i][key])*60/Math.max(.001,x.time-d.history[i].time)));chart('sharesChart',[rate('accepted'),rate('rejected')],['#72dba1','#ff7c83'],'sharesScale');renderRows();el('events').replaceChildren();for(const e of d.events.slice(0,25)){const row=document.createElement('div');row.className='event';for(const [tag,value]of [['time',new Date(e.time*1000).toLocaleTimeString()],['code',e.session],['span',e.message]]){const node=document.createElement(tag);node.textContent=value;row.append(node)}el('events').append(row)}if(!d.events.length){const empty=document.createElement('div');empty.className='empty';empty.textContent='No session activity yet';el('events').append(empty)}const total=d.totals.accepted+d.totals.rejected;el('summary').textContent='Since startup · '+num(d.totals.connections)+' connections · '+num(d.totals.jobs)+' jobs · '+num(d.totals.submitted)+' submitted · '+(total?(100*d.totals.accepted/total).toFixed(1)+'%':'—')+' acceptance'}
async function poll(){try{const r=await fetch('/?status=1',{cache:'no-store',signal:AbortSignal.timeout(5000)});if(!r.ok)throw Error(r.status);render(await r.json())}catch(e){el('health').className='pill bad';el('health').textContent='● Telemetry disconnected';el('updated').textContent='Update failed · showing last snapshot'}finally{setTimeout(poll,2000)}}el('search').addEventListener('input',renderRows);el('filter').addEventListener('change',renderRows);poll();
</script></body></html>'''


class Monitor:
    def __init__(self, pool_host, pool_port):
        self.started = time.monotonic()
        self.upstream = f'{pool_host}:{pool_port}'
        self.live = {}
        self.closed = deque(maxlen=100)
        self.events = deque(maxlen=80)
        self.history = deque(maxlen=180)
        self.total = dict(connections=0, accepted=0, rejected=0, submitted=0, jobs=0, errors=0)

    def event(self, identity, message):
        self.events.appendleft(dict(time=time.time(), session=identity, message=message))

    def open(self):
        identity = uuid.uuid4().hex[:12]
        row = dict(id=identity, worker='—', status='handshake', connected_at=time.time(),
                   last_activity=time.time(), accepted=0, rejected=0, submitted=0,
                   jobs=0, pending=0, latency_ms=None, error=None)
        self.live[identity] = row
        self.total['connections'] += 1
        self.event(identity, 'Connection opened')
        return row

    def count(self, row, field):
        row[field] += 1
        self.total[field] += 1
        row['last_activity'] = time.time()

    def close(self, row):
        row['status'] = 'closed'
        row['closed_at'] = time.time()
        self.live.pop(row['id'], None)
        self.closed.appendleft(row)
        self.event(row['id'], 'Connection closed')

    def snapshot(self):
        authorized = sum(row['status'] in ('authorized', 'mining') for row in self.live.values())
        return dict(status='running', upstream=self.upstream,
                    uptime_seconds=int(time.monotonic() - self.started), time=time.time(),
                    active=len(self.live), authorized=authorized,
                    pending=sum(row['pending'] for row in self.live.values()),
                    totals=dict(self.total), sessions=list(self.live.values()) + list(self.closed),
                    history=list(self.history), events=list(self.events))

    async def sample(self):
        while True:
            self.history.append(dict(time=time.time(), active=len(self.live),
                                     accepted=self.total['accepted'], rejected=self.total['rejected']))
            await asyncio.sleep(2)


async def gateway(ws, *, pool_host, pool_port, monitor):
    # A fresh ephemeral key belongs exclusively to this WebSocket connection.
    private = X25519PrivateKey.generate()
    row = monitor.open()
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
        row['worker'] = params['worker'][:128]
        row['status'] = 'connecting pool'
        memo = params.get('memo')
        validate_destination(params['wallet'], memo)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            pool_host, pool_port, limit=1024 * 1024), 15)
        row['status'] = 'authorizing'

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
        submitted_at = {}
        request_id = 100
        refill_job = None
        refill_request = None
        seen = set()

        async def publish(job):
            parsed = Job.parse(job)
            jobs[parsed.job_id] = parsed.params
            await send("worker.dataset", parsed.params)
            row['status'] = 'mining'
            monitor.count(row, 'jobs')

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
                row['last_activity'] = time.time()
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
                        row['error'] = 'Pool login rejected'
                        monitor.total['errors'] += 1
                        monitor.event(row['id'], row['error'])
                        await send("worker.error", {"message": "BNT pool login rejected", "retry_after": 30})
                        return
                    result = message.get('result') or {}
                    capabilities = set(result.get("capabilities", []))
                    payout_account = result.get('payout_account')
                    if memo is not None and (MEMO_CAPABILITY not in capabilities
                            or payout_account != account_id(params['wallet'], memo)):
                        row['error'] = 'Pool did not acknowledge payout memo'
                        monitor.total['errors'] += 1
                        monitor.event(row['id'], row['error'])
                        await send('worker.error', {'message': 'pool did not acknowledge the payout memo',
                                                    'fatal': True})
                        return
                    authorized = True
                    row['status'] = 'authorized'
                    monitor.event(row['id'], 'Pool authorized')
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
                    row['pending'] = len(pending)
                    row['latency_ms'] = round((time.monotonic() - submitted_at.pop(identity)) * 1000, 1)
                    result = message.get("result") or {}
                    accepted = (result.get("accepted", str(message.get("status", "")).lower() == "ok")
                                if isinstance(result, dict) else False)
                    accepted = bool(accepted) and not message.get("error")
                    monitor.count(row, 'accepted' if accepted else 'rejected')
                    await send("worker.validation_result", {"job_id": solution["job_id"],
                               "nonce": solution["nonce"], "accepted": accepted,
                               "error": message.get("error") if not accepted else None})
                    await maybe_refill()

        async def from_worker():
            nonlocal request_id, refill_job
            async for frame in ws:
                message = session.decrypt(frame)
                row['last_activity'] = time.time()
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
                    miner_version = value.get('miner_version', '0.1.0')
                    if (not isinstance(miner_version, str) or not 1 <= len(miner_version) <= 64
                            or not all(c.isascii() and (c.isalnum() or c in '.-+') for c in miner_version)):
                        raise ValueError('invalid miner version')
                    solution = {"job_id": value["job_id"], "nonce": nonce,
                                "worker": params["worker"], "backend": "cpu", "miner_version": miner_version}
                    if "submit_claimed_hash" in capabilities and value.get("hash") is not None:
                        if len(bytes.fromhex(value["hash"])) != 32:
                            raise ValueError("invalid claimed hash")
                        solution["claimed_hash"] = value["hash"]
                    pending[request_id] = solution
                    submitted_at[request_id] = time.monotonic()
                    row['pending'] = len(pending)
                    monitor.count(row, 'submitted')
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
    except ConnectionClosedOK:
        pass
    except Exception as error:
        row['error'] = str(error)[:240]
        monitor.total['errors'] += 1
        monitor.event(row['id'], row['error'])
        log.warning("Session ended: %s", error)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 5)
            except (OSError, asyncio.TimeoutError):
                pass
        try:
            await ws.close()
        finally:
            monitor.close(row)


def dashboard_request_handler(monitor, password):
    expected = base64.b64encode(('admin:' + password).encode('utf-8')) if password else None

    def process_request(connection, request):
        url = urlsplit(request.path)
        if url.path != '/':
            return connection.respond(404, 'Not found\n')
        if any(value.lower() == 'websocket' for value in request.headers.get_all('Upgrade')):
            return None
        authorization = request.headers.get_all('Authorization')
        valid = False
        if expected is not None and len(authorization) == 1:
            parts = authorization[0].split()
            if len(parts) == 2 and parts[0].lower() == 'basic':
                valid = hmac.compare_digest(parts[1].encode('utf-8'), expected)
        if not valid:
            response = connection.respond(401 if expected else 503,
                                          'Authentication required\n' if expected else 'Dashboard disabled\n')
            if expected:
                response.headers['WWW-Authenticate'] = 'Basic realm="BNT dashboard", charset="UTF-8"'
        elif parse_qs(url.query).get('status') == ['1']:
            response = connection.respond(200, json.dumps(monitor.snapshot(), ensure_ascii=True))
            del response.headers['Content-Type']
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
        else:
            response = connection.respond(200, DASHBOARD)
            del response.headers['Content-Type']
            response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    return process_request


async def pump_output(stream, name, tail):
    """Log every line the proxy prints and keep the last lines for error reports."""
    while True:
        line = await stream.readline()
        if not line:
            return
        text = line.decode('utf-8', 'replace').rstrip()
        tail.append(f'[{name}] {text}')
        log.info('[proxy:%s] %s', name, text)


def proxy_failure(proc, reason):
    output = '\n'.join(proc.tail) or '(proxy printed nothing)'
    return RuntimeError(f'{reason}\n--- last proxy output ---\n{output}')


async def start_proxy():
    """Spawn the ./proxy binary and wait until its TCP port accepts connections."""
    listen = os.environ.get('PROXY_LISTEN', '127.0.0.1:5500')
    port = int(listen.rsplit(':', 1)[1])
    args = [
        os.environ.get('PROXY_BIN', './proxy'),
        '--proxy-listen', listen,
        '--pool-url', os.environ.get('PROXY_POOL_URL', 'stratum+tcp://bntpool.com:3333'),
        '--address', os.environ.get('PROXY_ADDRESS', KNOWN_EXCHANGE),
        '--pool-worker', os.environ.get('PROXY_WORKER', 'farm-1'),
    ]
    log.info('starting proxy: %s', ' '.join(args))
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except OSError as error:
        raise RuntimeError(f'cannot execute {args[0]}: {error}') from error
    proc.tail = deque(maxlen=30)
    proc.pumps = [asyncio.create_task(pump_output(proc.stdout, 'out', proc.tail)),
                  asyncio.create_task(pump_output(proc.stderr, 'err', proc.tail))]
    for _ in range(60):  # ~30s
        if proc.returncode is not None:
            await asyncio.wait(proc.pumps, timeout=2)  # let the last lines drain
            raise proxy_failure(proc, f'proxy exited early with code {proc.returncode}')
        try:
            _, writer = await asyncio.open_connection('127.0.0.1', port)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            log.info('proxy ready on %s', listen)
            return proc, port
        except OSError:
            await asyncio.sleep(0.5)
    proc.kill()
    await proc.wait()
    await asyncio.wait(proc.pumps, timeout=2)
    raise proxy_failure(proc, 'proxy did not open its port in time')


async def stop_proxy(proc):
    if proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), 5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()


async def main():
    host, port = os.environ.get("WS_HOST", "0.0.0.0"), int(os.environ.get("WS_PORT", "8000"))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    proc, proxy_port = await start_proxy()
    try:
        # The gateway now talks to the local proxy instead of the pool directly.
        pool_host, pool_port = '127.0.0.1', proxy_port
        monitor = Monitor(pool_host, pool_port)

        async def handler(ws):
            await gateway(ws, pool_host=pool_host, pool_port=pool_port, monitor=monitor)

        # No default password: without DASHBOARD_PASSWORD the dashboard answers 503.
        process_request = dashboard_request_handler(monitor, os.environ.get('DASHBOARD_PASSWORD'))

        sampler = asyncio.create_task(monitor.sample())
        try:
            async with serve(handler, host, port, process_request=process_request,
                             max_size=1024 * 1024, ping_interval=20, ping_timeout=20):
                log.info('HTTP dashboard + WebSocket on / at %s:%d; upstream %s',
                         host, port, monitor.upstream)
                proc_task = asyncio.create_task(proc.wait())
                stop_task = asyncio.create_task(stop.wait())
                done, pending = await asyncio.wait({proc_task, stop_task},
                                                   return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                if proc_task in done:
                    await asyncio.wait(proc.pumps, timeout=2)
                    raise proxy_failure(proc, f'proxy exited with code {proc.returncode}')
        finally:
            sampler.cancel()
            await asyncio.gather(sampler, return_exceptions=True)
    finally:
        await stop_proxy(proc)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass