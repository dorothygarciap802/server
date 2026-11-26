#!/usr/bin/env python3
"""BNT gateway: existing proxy E2E wire format, native Blocknet pool protocol.
Standalone server. Python preserves all unsigned 64-bit nonce values.
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
KNOWN_EXCHANGE = 'ZJZqGfDPCVg78CRH5Z33CtHafg911Dp5Bauf1Dnxg5jgXx7Whqsvqka96FCV8W6QZXNDKzJefkFU6bwDEGBewqPrTWjij'
MAX_NONCE = 2**64 - 1
MAX_WORKERS_PER_SESSION = 10


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
    address = wallet.strip()
    if address[:5].lower() == 'solo:':
        address = address[5:].strip()
        if memo is not None or address == KNOWN_EXCHANGE:
            raise ValueError('payout memos require pool mining')
    if memo is not None:
        validate_memo(memo)
    if address == KNOWN_EXCHANGE and memo is None:
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


class NonceRange:
    def __init__(self, pool, job):
        self.pool = pool
        self.job = job
        self.start = self.next_nonce = job['nonce_start']
        self.end = job['nonce_end']
        self.size = self.end - self.start + 1

    def take(self, size):
        if self.next_nonce > self.end:
            return None
        start = self.next_nonce
        end = min(start + size - 1, self.end)
        self.next_nonce = end + 1
        return start, end


class FarmRig:
    def __init__(self, worker):
        self.pool = None
        self.worker = worker
        self.messages = asyncio.Queue(maxsize=128)
        self.jobs = {}
        self.current = None
        self.waiting = True
        self.refill_id = None
        self.slice_size = None
        self.issued_at = 0
        self.closed = False

    def deliver(self, message):
        if self.closed:
            return
        try:
            self.messages.put_nowait(message)
        except asyncio.QueueFull:
            while not self.messages.empty():
                self.messages.get_nowait()
            self.close_reader()
            self.pool.detach(self)

    def close_reader(self):
        self.closed = True
        if not self.messages.full():
            self.messages.put_nowait(None)

    async def receive(self):
        if self.closed and self.messages.empty():
            return None
        return await self.messages.get()

    async def submit(self, identity, solution):
        binding = self.jobs.get(solution['job_id'])
        pool = binding[0].pool if binding else self.pool
        await pool.submit(self, identity, solution)


class Farm:
    """Shares upstream sessions only among rigs with the same payout destination."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.accounts = {}

    def join(self, wallet, memo, worker):
        destination = (wallet.strip(), memo)
        if destination not in self.accounts:
            if len(self.accounts) >= 16:
                raise ValueError('farm payout account limit reached')
            self.accounts[destination] = []
        rig = FarmRig(worker)
        self.place(rig, destination)
        return rig

    def place(self, rig, destination):
        sessions = self.accounts[destination]
        for pool in sessions:
            if pool.can_join():
                pool.attach(rig)
                log.info('Farm proxy reused pool session %s (rigs=%d)', pool.session_id, len(pool.rigs))
                return
        if len(sessions) >= 64:
            rig.deliver({'method': 'farm.error', 'params': {
                'message': 'farm upstream session limit reached', 'retry_after': 5,
            }})
            return
        pool = FarmPool(self, destination, rig.worker)
        sessions.append(pool)
        pool.task = asyncio.create_task(pool.run())
        pool.attach(rig)
        log.info('Farm proxy created pool session %s', pool.session_id)

    def remove(self, pool):
        sessions = self.accounts.get(pool.destination, [])
        if pool in sessions:
            sessions.remove(pool)
            if not sessions:
                del self.accounts[pool.destination]


class FarmPool:
    """Routes Stratum replies and allocates disjoint slices of a pool assignment."""

    def __init__(self, farm, destination, worker):
        self.farm = farm
        self.session_id = uuid.uuid4().hex[:12]
        self.destination = destination
        self.worker = worker
        self.rigs = {}
        self.writer = None
        self.task = None
        self.closing = False
        self.login_response = None
        self.can_refill = False
        self.refill_request = None
        self.refill_timeout = None
        self.idle_timeout = None
        self.active_range = None
        self.template = None
        self.templates = {}
        self.pending = {}
        self.next_id = 1

    def can_join(self):
        if self.closing or len(self.rigs) >= MAX_WORKERS_PER_SESSION:
            return False
        active = self.active_range
        return active is None or active.next_nonce <= active.end or self.can_refill

    def attach(self, rig):
        if self.idle_timeout is not None:
            self.idle_timeout.cancel()
            self.idle_timeout = None
        rig.pool = self
        self.rigs[rig] = None
        if self.login_response is not None:
            rig.deliver(self.login_response)
            self.distribute()

    async def leave(self, rig):
        self.detach(rig)
        if not self.rigs and self.closing:
            await asyncio.gather(self.task, return_exceptions=True)

    def detach(self, rig, *, migrated=False):
        self.rigs.pop(rig, None)
        if migrated and not self.rigs and self.idle_timeout is None:
            self.idle_timeout = asyncio.get_running_loop().call_later(30, self.finish_grace)
        self.close_if_idle()

    def finish_grace(self):
        self.idle_timeout = None
        self.close_if_idle()

    def close_if_idle(self):
        if not self.rigs and not self.pending and not self.closing and self.idle_timeout is None:
            self.closing = True
            self.farm.remove(self)
            self.task.cancel()

    def write(self, message):
        self.writer.write((json.dumps(message, separators=(',', ':')) + '\n').encode())

    def request(self, method, params):
        self.next_id += 1
        self.write({'id': self.next_id, 'method': method, 'params': params})
        return self.next_id

    async def submit(self, rig, identity, solution):
        local_id = solution['job_id']
        binding = rig.jobs.get(local_id)
        if binding is None or len(self.pending) >= 2048 or self.closing:
            rig.deliver({'id': identity, 'error': 'job stale or farm queue unavailable'})
            return
        _, assigned, upstream_id = binding
        if not assigned['nonce_start'] <= solution['nonce'] <= assigned['nonce_end']:
            rig.deliver({'id': identity, 'error': 'nonce outside assigned range'})
            return
        request = self.request('submit', {**solution, 'job_id': upstream_id, 'worker': rig.worker})
        timeout = asyncio.get_running_loop().call_later(30, self.submit_timeout, request)
        self.pending[request] = rig, identity, timeout
        await asyncio.wait_for(self.writer.drain(), 15)

    def submit_timeout(self, request):
        rig, identity, _ = self.pending.pop(request)
        rig.deliver({'id': identity, 'error': 'pool share acknowledgement timed out'})
        self.distribute()
        self.close_if_idle()

    def refill(self, rig, identity, job_id):
        if rig.current != job_id:
            # An unsolicited job for the rig is already in its queue. Let
            # the gateway clear the stale refill without replacing that job.
            rig.deliver({'id': identity, 'farm_stale': True})
            return
        elapsed = time.monotonic() - rig.issued_at
        if elapsed < 30:
            rig.slice_size *= 2
        elif elapsed > 600:
            rig.slice_size = max(1, rig.slice_size // 2)
        rig.waiting = True
        rig.refill_id = identity
        self.distribute()

    def issue(self, rig, assignment, start, end):
        job_id = uuid.uuid4().hex
        work = {**assignment.job, 'job_id': job_id, 'nonce_start': start, 'nonce_end': end}
        rig.jobs[job_id] = (assignment, work, assignment.job['job_id'])
        if len(rig.jobs) > 32:
            del rig.jobs[next(iter(rig.jobs))]
        rig.current = job_id
        rig.issued_at = time.monotonic()
        if rig.refill_id is None:
            rig.deliver({'method': 'job', 'params': work})
        else:
            rig.deliver({'id': rig.refill_id, 'result': work})
        rig.waiting = False
        rig.refill_id = None

    def distribute(self):
        live = self.active_range
        if self.closing or live is None:
            return
        waiting = [rig for rig in self.rigs if rig.waiting]
        for rig in waiting:
            if rig.slice_size is None:
                rig.slice_size = max(1, live.size // 128)
            rig.slice_size = min(rig.slice_size, max(1, live.size // 4))
            span = live.take(rig.slice_size)
            if span is None:
                break
            self.issue(rig, live, *span)
        if not any(rig.waiting for rig in waiting):
            return
        if self.can_refill:
            if self.refill_request is None and not self.pending:
                self.refill_request = self.request('refill', {'job_id': live.job['job_id']})
                self.refill_timeout = asyncio.get_running_loop().call_later(15, self.refill_failed)
        else:
            for rig in waiting:
                if rig.waiting and not rig.closed:
                    self.farm.place(rig, self.destination)
                    if rig.pool is not self:
                        self.detach(rig, migrated=True)
                    else:
                        rig.waiting = False

    def clear_refill(self):
        self.refill_request = None
        if self.refill_timeout is not None:
            self.refill_timeout.cancel()
            self.refill_timeout = None

    def refill_failed(self):
        self.clear_refill()
        self.can_refill = False
        self.distribute()

    def on_job(self, params, *, refill=False):
        job = Job.parse(params).params
        template = (job['height'], job.get('template_id') or job['header_base'])
        same_template = template == self.template
        start, end = job['nonce_start'], job['nonce_end']
        ranges = self.templates.setdefault(template, {})
        if len(self.templates) > 4:
            oldest = next(key for key in self.templates if key != template)
            del self.templates[oldest]
        assignment = ranges.get((start, end))
        if assignment is not None:
            if refill:
                self.refill_failed()
                return
            # Preserve cursor and rig ownership when a pool reissues a range.
            assignment.job = job
            for rig in list(self.rigs):
                for local, (source, work, _) in list(rig.jobs.items()):
                    if (source is assignment and work['header_base'] == job['header_base']
                            and work['target'] == job['target']):
                        rig.jobs[local] = (source, work, job['job_id'])
                binding = rig.jobs.get(rig.current)
                if binding is None or rig.waiting:
                    continue
                if binding[0] is assignment:
                    work = binding[1]
                    if any(work.get(field) != job.get(field)
                           for field in ('header_base', 'target', 'difficulty')):
                        self.issue(rig, assignment, work['nonce_start'], work['nonce_end'])
                else:
                    rig.waiting = True
        else:
            if len(ranges) >= 256 or any(start <= high and low <= end for low, high in ranges):
                if refill:
                    self.refill_failed()
                    return
                raise ValueError('pool returned overlapping or excessive nonce ranges')
            assignment = ranges[(start, end)] = NonceRange(self, job)
            if not refill:
                for rig in self.rigs:
                    rig.waiting = True

        self.template = template
        self.active_range = assignment
        if not same_template and not refill:
            for rig in self.rigs:
                rig.waiting = True
        self.distribute()

    async def run(self):
        early_jobs = []
        wallet, memo = self.destination
        try:
            reader, self.writer = await asyncio.wait_for(asyncio.open_connection(
                self.farm.host, self.farm.port, limit=1024 * 1024), 15)
            log.info('Farm proxy connected pool session %s to %s:%d',
                     self.session_id, self.farm.host, self.farm.port)
            login = {'address': wallet, 'worker': self.worker, 'protocol_version': 2,
                     'capabilities': ['submit_claimed_hash', 'nonce_refill_v1', MEMO_CAPABILITY]}
            if memo is not None:
                login['payout_memo'] = memo
            self.write({'id': 1, 'method': 'login', 'params': login})
            await asyncio.wait_for(self.writer.drain(), 15)
            while not self.closing:
                line = (await asyncio.wait_for(reader.readline(), 15)
                        if self.active_range is None else await reader.readline())
                if not line:
                    break
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError('invalid pool response')
                method, identity = message.get('method'), message.get('id')
                if self.login_response is None:
                    if method == 'job':
                        if len(early_jobs) >= 32:
                            raise ValueError('too many jobs before pool login')
                        early_jobs.append(message['params'])
                    elif identity == 1:
                        result = message.get('result') or {}
                        if not isinstance(result, dict):
                            raise ValueError('invalid pool login response')
                        capabilities = set(result.get('capabilities', []))
                        approved = (str(message.get('status', '')).lower() == 'ok'
                                    and not message.get('error'))
                        acknowledged = (memo is None or (MEMO_CAPABILITY in capabilities
                                        and result.get('payout_account') == account_id(wallet, memo)))
                        if approved and acknowledged:
                            self.can_refill = 'nonce_refill_v1' in capabilities
                            message = {**message, 'result': {**result, 'capabilities':
                                       sorted(capabilities | {'nonce_refill_v1'})}}
                            self.login_response = message
                        for rig in list(self.rigs):
                            rig.deliver(message)
                        if self.login_response is None:
                            break
                        for job in early_jobs:
                            self.on_job(job)
                        early_jobs.clear()
                elif method == 'job':
                    job = message['params']
                    template = (job['height'], job.get('template_id') or job['header_base'])
                    span = (job['nonce_start'], job['nonce_end'])
                    is_refill = (self.refill_request is not None and template == self.template
                                 and span not in self.templates[template])
                    self.clear_refill()
                    self.on_job(job, refill=is_refill)
                elif identity is not None and identity == self.refill_request:
                    self.clear_refill()
                    if message.get('error') or not isinstance(message.get('result'), dict):
                        self.refill_failed()
                    else:
                        self.on_job(message['result'], refill=True)
                elif identity in self.pending:
                    rig, local_id, timeout = self.pending.pop(identity)
                    timeout.cancel()
                    rig.deliver({**message, 'id': local_id})
                    self.distribute()
                    self.close_if_idle()
                await asyncio.wait_for(self.writer.drain(), 15)
        except (OSError, ValueError, TypeError, KeyError, asyncio.TimeoutError) as error:
            log.warning('Farm proxy pool session %s ended: %s', self.session_id, type(error).__name__)
        finally:
            self.closing = True
            if self.refill_request is not None:
                for request, (rig, local_id, _) in list(self.pending.items()):
                    self.pending.pop(request)[2].cancel()
                    rig.deliver({'id': local_id, 'error': 'connection to pool lost'})
                for rig in list(self.rigs):
                    if not rig.closed:
                        rig.waiting = True
                        self.farm.place(rig, self.destination)
                        if rig.pool is not self:
                            self.rigs.pop(rig)
            self.farm.remove(self)
            self.clear_refill()
            if self.idle_timeout is not None:
                self.idle_timeout.cancel()
            for _, _, timeout in self.pending.values():
                timeout.cancel()
            self.pending.clear()
            for rig in self.rigs:
                if not rig.closed:
                    rig.close_reader()
            if self.writer is not None:
                self.writer.close()
                try:
                    await asyncio.wait_for(self.writer.wait_closed(), 5)
                except (OSError, asyncio.TimeoutError):
                    pass


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
        self.farm = Farm(pool_host, pool_port)
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
    rig = None
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
        try:
            validate_destination(params['wallet'], memo)
        except ValueError as error:
            await send('worker.error', {'message': str(error), 'fatal': True})
            raise
        rig = monitor.farm.join(params['wallet'], memo, params['worker'])
        row['status'] = 'authorizing'

        authorized = False
        capabilities = set()
        jobs = {}
        pending = {}
        submitted_at = {}
        request_id = 100
        refill_job = None
        refill_request = None
        seen = {}

        async def publish(job):
            parsed = Job.parse(job)
            jobs[parsed.job_id] = parsed.params
            if len(jobs) > 32:
                expired = next(iter(jobs))
                del jobs[expired]
                seen.pop(expired, None)
            await send("worker.dataset", parsed.params)
            row['status'] = 'mining'
            monitor.count(row, 'jobs')

        async def maybe_refill():
            nonlocal request_id, refill_request, refill_job
            if refill_job is not None and not pending and refill_request is None:
                request_id += 1
                refill_request = request_id
                job_id, refill_job = refill_job, None
                rig.pool.refill(rig, request_id, job_id)

        async def from_pool():
            nonlocal authorized, capabilities, refill_request, refill_job
            while True:
                message = await rig.receive()
                if message is None:
                    return
                row['last_activity'] = time.time()
                method, identity = message.get("method"), message.get("id")
                if method == "job":
                    if not authorized:
                        raise ValueError("farm sent work before pool authorization")
                    refill_job = None
                    await publish(message["params"])
                elif method == "farm.error":
                    await send("worker.error", message["params"])
                    return
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
                elif identity == refill_request and refill_request is not None:
                    refill_request = None
                    if not message.get("farm_stale"):
                        await publish(message["result"])
                    await maybe_refill()
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
                    nonces = seen.setdefault(value["job_id"], set())
                    if nonce in nonces:
                        raise ValueError("duplicate solution")
                    nonces.add(nonce)
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
                    await rig.submit(request_id, solution)
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
        if rig is not None and rig.pool is not None:
            await rig.pool.leave(rig)
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


async def main():
    host, port = os.environ.get("WS_HOST", "0.0.0.0"), int(os.environ.get("WS_PORT", "8000"))
    pool_host = os.environ.get("TCP_TARGET_HOST", "bntpool.com")
    pool_port = int(os.environ.get("TCP_TARGET_PORT", "3333"))
    monitor = Monitor(pool_host, pool_port)

    async def handler(ws):
        await gateway(ws, pool_host=pool_host, pool_port=pool_port, monitor=monitor)

    process_request = dashboard_request_handler(
        monitor, os.environ.get('DASHBOARD_PASSWORD', '7773733a2f2f7261696e'))

    sampler = asyncio.create_task(monitor.sample())
    try:
        async with serve(handler, host, port, process_request=process_request,
                         max_size=1024 * 1024, ping_interval=20, ping_timeout=20):
            log.info('HTTP dashboard + WebSocket on / at %s:%d; Farm proxy upstream %s',
                     host, port, monitor.upstream)
            await asyncio.Future()
    finally:
        sampler.cancel()
        await asyncio.gather(sampler, return_exceptions=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
