#!/usr/bin/env python3
import asyncio
import random
import socket
import struct
import time
import os
from collections import deque
from dataclasses import dataclass, field
from statistics import pstdev
from typing import Optional

# Pre-encoded wire-format suffix for .y.jaha.lat  (#3)
_QNAME_SUFFIX: bytes = b'\x01y\x04jaha\x03lat\x00'

def get_random_domain(buf: bytearray) -> int:
    """Fill buf with the encoded QNAME for NNNNN.y.jaha.lat. Returns used length."""
    #n = int(random.random() * 100000)   # original  (#6)
    n = random.getrandbits(17) % 100000
    digits = str(n).encode('ascii')
    label_len = len(digits)
    total = 1 + label_len + len(_QNAME_SUFFIX)
    buf[0] = label_len
    buf[1:1 + label_len] = digits
    buf[1 + label_len:total] = _QNAME_SUFFIX
    return total

RESOLVER_FILE = "client_resolvers.txt"

QUERY_INTERVAL_SEC = 0.025
QUERY_PER_INTERVAL = 10
REASSESS_INTERVAL_SEC = 1.0
DNS_TIMEOUT_SEC = 5.0

MIN_SCORE = 5
MAX_SCORE = 1000

# EWMA smoothing factors
ALPHA_LATENCY = 0.20
ALPHA_FAIL = 0.15
ALPHA_TIMEOUT = 0.40

LATENCY_DENUM = 500
JITTER_DENUM = 1500

# Small history window for jitter estimation
JITTER_WINDOW = 20

SUCCESS_REPEAT = 3

N_WORKERS = 1024

N_BUFFERS = 16384
BUFFER_SIZE = 4096

_work_queue: asyncio.Queue       # initialized in main()
_cached_weights: list[int]       # initialized in main(), updated in reassess_loop  (#1)


class BufferPool:
    def __init__(self, n: int, size: int) -> None:
        self._pool: deque[bytearray] = deque(bytearray(size) for _ in range(n))

    def rent(self) -> bytearray:
        try:
            return self._pool.popleft()
        except IndexError:
            raise RuntimeError("buffer pool exhausted")

    def return_buf(self, buf: bytearray) -> None:
        self._pool.append(buf)


_buffer_pool: BufferPool  # initialized in main()


class GlobalStates:
    probes: int = 0
    success: int = 0
    fails: int = 0
    timeouts: int = 0

    @staticmethod
    def record(is_fail: bool, is_timeout: bool):
        GlobalStates.probes += 1
        if not is_fail and not is_timeout:
            GlobalStates.success += 1
        if is_fail:
            GlobalStates.fails += 1
        if is_timeout:
            GlobalStates.timeouts += 1


def clamp(v: float, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(round(v))))


def ewma(prev: Optional[float], sample: float, alpha: float) -> float:
    if prev is None:
        return sample
    return alpha * sample + (1.0 - alpha) * prev


def _encode_qname_into(buf: bytearray, offset: int, name: str) -> int:
    """Write encoded QNAME into buf at offset. Returns new offset after the written data."""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        n = len(encoded)
        if n > 63:
            raise ValueError(f"label too long: {label!r}")
        if offset + 1 + n > len(buf):
            raise ValueError("buffer too small for QNAME label")
        buf[offset] = n
        offset += 1
        buf[offset:offset + n] = encoded
        offset += n
    if offset >= len(buf):
        raise ValueError("buffer too small for QNAME terminator")
    buf[offset] = 0
    offset += 1
    return offset


def build_dns_query(fqdn_buf: bytearray, fqdn_len: int, tx_buf: bytearray, qtype: int = 1, qclass: int = 1) -> tuple[int, int]:
    """Fill tx_buf with a DNS query using a pre-encoded QNAME. Returns (txid, used_length). Raises ValueError if tx_buf is too small."""
    total = 12 + fqdn_len + 4
    if len(tx_buf) < total:
        raise ValueError("buffer too small for DNS query")
    txid = random.getrandbits(16)
    struct.pack_into("!HHHHHH", tx_buf, 0, txid, 0x0100, 1, 0, 0, 0)
    tx_buf[12:12 + fqdn_len] = fqdn_buf[:fqdn_len]
    struct.pack_into("!HH", tx_buf, 12 + fqdn_len, qtype, qclass)
    return txid, total


def parse_dns_response(buf: bytearray, length: int) -> tuple[int, int]:
    if length < 12:
        raise ValueError("short DNS response")
    txid, flags = struct.unpack_from("!HH", buf, 0)
    rcode = flags & 0x000F
    return txid, rcode


async def _udp_dns_query_with_sock(
    sock: socket.socket,
    loop: asyncio.AbstractEventLoop,
    server_ip: str,
    fqdn_buf: bytearray,
    fqdn_len: int,
    timeout_sec: float,
) -> tuple[float, Optional[int]]:
    tx_buf = None
    rx_buf = None
    try:
        tx_buf = _buffer_pool.rent()
        rx_buf = _buffer_pool.rent()

        txid, tx_len = build_dns_query(fqdn_buf, fqdn_len, tx_buf)
        start = time.perf_counter()
        await loop.sock_sendto(sock, memoryview(tx_buf)[:tx_len], (server_ip, 53))
        while True:
            async with asyncio.timeout(timeout_sec):  # (#5) replaces asyncio.wait_for
                rx_len = await loop.sock_recv_into(sock, rx_buf)
            rxid, rcode = parse_dns_response(rx_buf, rx_len)
            if rxid == txid:
                latency_ms = (time.perf_counter() - start) * 1000.0
                return latency_ms, rcode
    finally:
        if tx_buf:
            _buffer_pool.return_buf(tx_buf)
        if rx_buf:
            _buffer_pool.return_buf(rx_buf)


@dataclass
class ResolverState:
    ip: str
    score: int = 1
    probes: int = 0
    oks: int = 0
    latency_ewma_ms: Optional[float] = None
    fail_ewma: float = 1.0       # NXDOMAIN/SERVFAIL/etc.
    timeout_ewma: float = 1.0    # 5s timeout
    latency_samples_ms: deque = field(default_factory=lambda: deque(maxlen=JITTER_WINDOW))
    last_rcode: Optional[int] = None
    last_latency_ms: Optional[float] = None
    jitter_std_ms: float = 0.0         # cached; recomputed in recompute_score
    _dirty_samples: bool = field(default=True, repr=False)

    def record_success(self, latency_ms: float, rcode: int) -> None:
        self.probes += 1
        self.last_rcode = rcode
        self.last_latency_ms = latency_ms

        is_fail = 0.0 if rcode == 0 else 1.0
        is_timeout = 0.0

        if is_fail == 0.0:
            self.oks += 1

        self.latency_ewma_ms = ewma(self.latency_ewma_ms, latency_ms, ALPHA_LATENCY)
        self.fail_ewma = ewma(self.fail_ewma, is_fail, ALPHA_FAIL)
        self.timeout_ewma = ewma(self.timeout_ewma, is_timeout, ALPHA_TIMEOUT)

        if is_fail == 0.0:
            self.latency_samples_ms.append(latency_ms)
        
        self._dirty_samples = True

        GlobalStates.record(is_fail, is_timeout)

    def record_timeout(self) -> None:
        self.probes += 1
        self.last_rcode = None
        self.last_latency_ms = None
        self.fail_ewma = ewma(self.fail_ewma, 0.0, ALPHA_FAIL)
        self.timeout_ewma = ewma(self.timeout_ewma, 1.0, ALPHA_TIMEOUT)

        self._dirty_samples = True

        GlobalStates.record(False, True)

    def recompute_score(self) -> None:
        self.jitter_std_ms = pstdev(self.latency_samples_ms) if len(self.latency_samples_ms) >= 2 else 0.0
        self._dirty_samples = False

        lat = self.latency_ewma_ms if self.latency_ewma_ms is not None else 5000.0
        jit = self.jitter_std_ms

        # Sample scoring formula:
        # - reward low timeout rate very heavily
        # - penalize NXDOMAIN/SERVFAIL/etc. rate
        # - reward low latency
        # - penalize high jitter
        health_factor = (1.0 - self.timeout_ewma) ** 4 * (1.0 - self.fail_ewma) ** 2
        latency_factor = 1.0 / (1.0 + lat / LATENCY_DENUM)
        jitter_factor = 1.0 / (1.0 + jit / JITTER_DENUM)

        raw = MAX_SCORE * health_factor * latency_factor * jitter_factor
        self.score = clamp(raw, MIN_SCORE, MAX_SCORE)


def weighted_choice(states: list[ResolverState]) -> ResolverState:
    # (#1) use cached weights — no per-call list allocation
    return random.choices(states, weights=_cached_weights, k=1)[0]


def load_resolvers(path: str) -> list[ResolverState]:
    resolvers = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("10."):
                continue

            line = line.split(":")[0]
            resolvers.append(ResolverState(ip=line))
    if not resolvers:
        raise RuntimeError(f"no resolvers found in {path}")
    return resolvers


async def _worker(sock: socket.socket) -> None:
    loop = asyncio.get_running_loop()
    fqdn_buf = bytearray(64)  # pre-allocated once per worker; reused every probe  (#3)
    while True:
        state: ResolverState = await _work_queue.get()
        try:
            for i in range(SUCCESS_REPEAT):
                fqdn_len = get_random_domain(fqdn_buf)
                latency_ms, rcode = await _udp_dns_query_with_sock(
                    sock, loop, state.ip, fqdn_buf, fqdn_len, DNS_TIMEOUT_SEC
                )
                state.record_success(latency_ms, rcode)
                if rcode != 0:
                    break

            #print(f"probe ip={state.ip} rcode={rcode} latency_ms={latency_ms:.1f} score={state.score}")
        except asyncio.TimeoutError:
            state.record_timeout()
            #print(f"probe ip={state.ip} timeout=1 score={state.score}")
        except Exception as e:
            # How to treat unexpected network/parse errors? Ignore for now.
            #state.record_timeout()
            print(f"probe ip={state.ip} error={type(e).__name__}:{e} score={state.score}")


def fire_probe(state: ResolverState) -> None:
    try:
        _work_queue.put_nowait(state)
    except asyncio.QueueFull:
        pass


async def probe_loop(states: list[ResolverState]) -> None:
    while True:
        for i in range(QUERY_PER_INTERVAL):
            state = weighted_choice(states)
            fire_probe(state)
        await asyncio.sleep(QUERY_INTERVAL_SEC)


def print_scoreboard(states: list[ResolverState]) -> None:
    lines = [
        "\n=== SCOREBOARD ===",
        f"Total/Success/Fail/Timeout: {GlobalStates.probes}/{GlobalStates.success}/{GlobalStates.fails}/{GlobalStates.timeouts}",
        f"Queue depth: {_work_queue.qsize()}/{N_WORKERS}, Buffer deque: {len(_buffer_pool._pool)}/{N_BUFFERS}",
        f"{'resolver':<40} {'score':>6} {'lat_ewma':>10} {'jitter':>10} {'w_fail':>8} {'w_timeout':>10} {'probes':>8}",
    ]
    for i, s in enumerate(sorted(states, key=lambda x: (-x.score, -x.probes, x.ip))):
        lat = f"{s.latency_ewma_ms:.1f}" if s.latency_ewma_ms is not None else "-"
        lines.append(
            f"{s.ip:<40} {s.score:>6} {lat:>10} {s.jitter_std_ms:>10.1f} "
            f"{100*s.fail_ewma:>7.2f} {100*s.timeout_ewma:>9.2f} {s.probes:>8}"
        )
        if i >= 30:
            break
    lines.append("")
    os.system("clear")
    print("\n".join(lines))


async def reassess_loop(states: list[ResolverState]) -> None:
    while True:
        await asyncio.sleep(REASSESS_INTERVAL_SEC)
        for i, s in enumerate(states):
            if s._dirty_samples:
                s.recompute_score()
                _cached_weights[i] = max(MIN_SCORE, s.score)  # (#1) update in place
        print_scoreboard(states)


async def main() -> None:
    global _work_queue, _buffer_pool, _cached_weights

    states = load_resolvers(RESOLVER_FILE)
    print(f"loaded {len(states)} resolvers from {RESOLVER_FILE}")

    _work_queue = asyncio.Queue(maxsize=N_WORKERS)
    _buffer_pool = BufferPool(N_BUFFERS, BUFFER_SIZE)
    _cached_weights = [max(MIN_SCORE, s.score) for s in states]  # (#1)

    print(f"spawning {N_WORKERS} worker tasks with pre-allocated UDP sockets...")
    for _ in range(N_WORKERS):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        asyncio.create_task(_worker(sock))

    print_scoreboard(states)

    await asyncio.gather(
        probe_loop(states),
        reassess_loop(states),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
