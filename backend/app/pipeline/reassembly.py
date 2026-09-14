"""TCP flow tracking and stream reassembly from raw pcap packets.

Bounded-memory design: segments are merged into byte buffers as they
arrive; per-flow caps prevent a hostile/odd capture from exhausting RAM.

Forensic honesty: a stream with a missing segment is never concatenated
as if contiguous — reassembly stops at the first hole and the stream is
flagged `reassembly_incomplete`. Streams cut by the size cap are flagged
`truncated`. Both flags surface on the session and in the reports.
"""
from __future__ import annotations

from dataclasses import dataclass, field

MOD32 = 1 << 32
MAX_STREAM_BYTES = 4 * 1024 * 1024        # per direction, enough for mail+TLS
MAX_FLOWS = 5000


def seq_unwrap(base: int, seq: int) -> int:
    """Map a 32-bit TCP sequence number onto a signed offset from `base`,
    handling wraparound: values within [base, base+2^31) are "after" base,
    the rest are "before" (RFC 1983 serial-number arithmetic)."""
    delta = (seq - base) % MOD32
    return delta if delta < MOD32 // 2 else delta - MOD32


@dataclass
class Segment:
    seq: int
    data: bytes
    ts: float
    frame_no: int = 0          # pcap frame that carried this segment
    syn: bool = False
    fin: bool = False
    rst: bool = False


@dataclass
class DirectionStream:
    segments: list[Segment] = field(default_factory=list)
    _buffer: bytes | None = None
    start_ts: float | None = None
    end_ts: float | None = None
    total_bytes: int = 0
    first_frame: int = 0        # first pcap frame seen on this direction
    reassembly_incomplete: bool = False   # a hole was seen; stream stops there
    hole_at: int | None = None            # unwrapped seq offset of the hole
    truncated: bool = False               # hit the per-direction byte cap

    def add(self, seg: Segment) -> None:
        if self.start_ts is None or seg.ts < self.start_ts:
            self.start_ts = seg.ts
        if self.end_ts is None or seg.ts > self.end_ts:
            self.end_ts = seg.ts
        self.total_bytes += len(seg.data)
        if self.total_bytes > MAX_STREAM_BYTES:
            self.truncated = True       # cap: drop tail of pathological flows
            return
        if not self.first_frame and seg.frame_no:
            self.first_frame = seg.frame_no
        self.segments.append(seg)
        self._buffer = None

    def reassemble(self) -> bytes:
        """Sort by sequence (wraparound-aware), drop retransmissions and
        overlaps, concatenate. Stops at the first gap rather than inventing
        contiguity a forensic tool cannot prove."""
        if self._buffer is not None:
            return self._buffer
        segs = [s for s in self.segments if s.data and not s.syn]
        if not segs:
            self._buffer = b""
            self.segments = []
            return b""
        # unwrap sequence numbers relative to the first segment we hold so
        # wraparound (seq near 2^32 rolling to 0) sorts correctly.
        base = segs[0].seq
        segs.sort(key=lambda s: seq_unwrap(base, s.seq))
        out = bytearray()
        expected = 0                                   # unwrapped offset space
        first = True
        for s in segs:
            off = seq_unwrap(base, s.seq)
            if first:
                expected = off
                first = False
            if off + len(s.data) <= expected:
                continue                              # fully retransmitted
            if off > expected:
                # hole: bytes [expected, off) never arrived. Stop here —
                # concatenating would fabricate a byte stream that never
                # existed on the wire.
                self.reassembly_incomplete = True
                self.hole_at = expected
                break
            skip = expected - off
            out += s.data[skip:]
            expected = off + len(s.data)
        self._buffer = bytes(out[:MAX_STREAM_BYTES])
        self.segments = []                        # free raw segments
        return self._buffer


@dataclass
class Flow:
    """A bidirectional TCP conversation."""
    src: str; sport: int
    dst: str; dport: int
    c2s: DirectionStream = field(default_factory=DirectionStream)
    s2c: DirectionStream = field(default_factory=DirectionStream)
    start_ts: float = 0.0
    end_ts: float = 0.0
    client_first: bool = True        # who spoke first (server banners flip this)
    saw_syn_from_src: bool = False
    saw_synack_from_dst: bool = False
    flow_key: tuple = ()

    @property
    def duration_ms(self) -> int:
        if not self.start_ts or not self.end_ts:
            return 0
        return int((self.end_ts - self.start_ts) * 1000)


class FlowTable:
    def __init__(self) -> None:
        self.flows: dict[tuple, Flow] = {}
        self.overflowed = 0

    @staticmethod
    def _key(a: tuple, b: tuple) -> tuple:
        return (a, b) if a <= b else (b, a)

    def add_packet(self, src: str, sport: int, dst: str, dport: int,
                   seq: int, payload: bytes, ts: float, frame_no: int = 0,
                   syn: bool = False, fin: bool = False, rst: bool = False) -> None:
        a, b = (src, sport), (dst, dport)
        key = self._key(a, b)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= MAX_FLOWS:
                self.overflowed += 1
                return
            flow = Flow(src=a[0], sport=a[1], dst=b[0], dport=b[1], flow_key=key)
            self.flows[key] = flow
        forward = (a == (flow.src, flow.sport))
        if syn and not flow.saw_synack_from_dst:
            if forward:
                flow.saw_syn_from_src = True
            else:
                flow.saw_synack_from_dst = True
        seg = Segment(seq=seq, data=payload, ts=ts, frame_no=frame_no, syn=syn, fin=fin, rst=rst)
        if forward:
            flow.c2s.add(seg)
        else:
            flow.s2c.add(seg)
        if not flow.start_ts or ts < flow.start_ts:
            flow.start_ts = ts
        if ts > flow.end_ts:
            flow.end_ts = ts

    def finished_flows(self, min_bytes: int = 1) -> list[Flow]:
        return [f for f in self.flows.values()
                if f.c2s.total_bytes + f.s2c.total_bytes >= min_bytes]
