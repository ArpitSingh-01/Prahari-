"""PCAP ingest: normalize any supported link layer into TCP packet tuples."""
from __future__ import annotations

import ipaddress
from typing import Iterator

import dpkt

MAX_PCAP_BYTES = 25 * 1024 * 1024

LINK_HANDLERS = {}


def _iter_eth(buf: bytes):
    eth = dpkt.ethernet.Ethernet(buf)
    return eth.type, eth.data


def _iter_sll(buf: bytes):
    sll = dpkt.sll.SLL(buf)
    return sll.htype, sll.data


def _iter_raw(buf: bytes):
    return dpkt.consts.ETHERNET_TYPE_IP, buf


READERS = {
    dpkt.pcap.DLT_EN10MB: _iter_eth,
    dpkt.pcap.DLT_LINUX_SLL: _iter_sll,
    dpkt.pcap.DLT_RAW: _iter_raw,
    101: _iter_raw,             # DLT_RAW on some platforms
}


def read_pcap(data: bytes) -> Iterator[tuple]:
    """Yield (ts, src, sport, dst, dport, seq, flags, payload, frame_no,
    file_offset) for TCP packets. frame_no is the packet's 1-based position
    in the capture and file_offset the byte offset of its record/block start
    in the file (both counted before any filtering, so frame_no matches
    Wireshark's "No." column). Raises ValueError on bad input."""
    if len(data) < 24:
        raise ValueError("file too small to be a pcap")
    magic = data[:4]
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") and \
       magic != b"\x0a\x0d\x0d\x0a":
        raise ValueError("not a pcap/pcapng file (bad magic bytes)")

    if magic == b"\x0a\x0d\x0d\x0a":
        reader = _read_pcapng(data)
    else:
        reader = _read_classic(data)
    return reader


def _read_classic(data: bytes):
    try:
        fh = __import__("io").BytesIO(data)
        reader = dpkt.pcap.Reader(fh)
    except Exception as exc:
        raise ValueError("unreadable pcap: %s" % exc)
    handler = READERS.get(reader.datalink())
    if handler is None:
        raise ValueError("unsupported link type %s" % reader.datalink())

    def gen():
        frame_no = 0
        it = iter(reader)
        while True:
            try:
                offset = fh.tell()          # record start: dpkt reads sequentially
            except Exception:
                offset = -1
            try:
                ts, buf = next(it)
            except StopIteration:
                return
            frame_no += 1
            try:
                etype, net = handler(buf)
            except Exception:
                continue
            if not isinstance(net, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            if net.p != dpkt.ip.IP_PROTO_TCP:
                continue
            tcp = net.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            try:
                src = str(ipaddress.ip_address(net.src))
                dst = str(ipaddress.ip_address(net.dst))
            except Exception:
                continue
            payload = bytes(tcp.data) if tcp.data else b""
            yield (float(ts), src, int(tcp.sport), dst, int(tcp.dport),
                   int(tcp.seq), int(tcp.flags), payload, frame_no, offset)

    return gen()


def _read_pcapng(data: bytes):
    try:
        fh = __import__("io").BytesIO(data)
        reader = dpkt.pcapng.Reader(fh)
    except Exception as exc:
        raise ValueError("unreadable pcapng: %s" % exc)
    dlt = getattr(reader, "datalink", lambda: 1)()

    def gen():
        handler = READERS.get(dlt)
        if handler is None:
            return
        frame_no = 0
        it = iter(reader)
        while True:
            try:
                offset = fh.tell()          # block start: dpkt reads sequentially
            except Exception:
                offset = -1
            try:
                ts, buf = next(it)
            except StopIteration:
                return
            frame_no += 1
            try:
                etype, net = handler(bytes(buf))
            except Exception:
                continue
            if not isinstance(net, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            if net.p != dpkt.ip.IP_PROTO_TCP:
                continue
            tcp = net.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            src = str(ipaddress.ip_address(net.src))
            dst = str(ipaddress.ip_address(net.dst))
            payload = bytes(tcp.data) if tcp.data else b""
            yield (float(ts), src, int(tcp.sport), dst, int(tcp.dport),
                   int(tcp.seq), int(tcp.flags), payload, frame_no, offset)

    return gen()
