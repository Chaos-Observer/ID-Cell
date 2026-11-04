"""Deterministic, standard-library-only v0.11 protocol design simulator."""
from __future__ import annotations

import hashlib
import heapq
import hmac
import math
import random
import struct
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence, cast

VERSION_MAJOR = 0
VERSION_MINOR = 11
VERSION = (VERSION_MAJOR << 4) | VERSION_MINOR
PROTOCOL_VERSION = "v0.11"
SYNC = b"\xA5\xA5"
TRAILER = b"\x5A\xA5"
# SYNC (2) + the named fields (34) form the 36-byte fixed header.
HEADER_LEN = 36
AUTH_FLAG = 0x20
AUTH_TAG_LEN = 16
PROF_STD = 0
PROF_RT = 1
TYPE_DISCOVER = 0x01
TYPE_HELLO = 0x02
TYPE_MATCH = 0x03
TYPE_NEGOTIATE = 0x04
TYPE_RENEGOTIATE = 0x05
TYPE_AUTH = 0x06
TYPE_BIND = 0x07
TYPE_READ = 0x08
TYPE_WRITE = 0x09
TYPE_SUBSCRIBE = 0x0A
TYPE_UNSUB = 0x0B
TYPE_EVENT = 0x0C
TYPE_CMD = 0x0D
TYPE_ACK = 0x0E
TYPE_DONE = 0x0F
TYPE_LEASE = 0x10
TYPE_PREEMPT = 0x11
TYPE_GROUP = 0x12
TYPE_HEARTBEAT = 0x13
TYPE_OFFLINE = 0x14
TYPE_STALE = 0x15
TYPE_CONFIG = 0x16
TYPE_PROVISION = 0x17
TYPE_ERROR = 0x18
TYPE_RT_DATA = 0x19
VALID_TYPES = frozenset(range(1, 26))
U64_MAX = (1 << 64) - 1


def crc16_ccitt_false(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: polynomial 0x1021, initial value 0xFFFF."""
    crc = 0xFFFF
    for octet in data:
        crc ^= octet << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _u64(value: int, name: str) -> bytes:
    if not 0 <= value <= U64_MAX:
        raise ValueError(f"{name} is not u64")
    return value.to_bytes(8, "big")


def _ts6(value: int) -> bytes:
    if not 0 <= value < (1 << 48):
        raise ValueError("ts is not u48")
    return value.to_bytes(6, "big")


def valid_version(version: int) -> bool:
    # Frame acceptance checks only major compatibility; minor feature intersection is negotiated later.
    return version >> 4 == VERSION_MAJOR


@dataclass(frozen=True)
class Frame:
    payload: bytes = b""
    ver: int = VERSION
    prof: int = PROF_STD
    flags: int = 0
    frame_type: int = TYPE_DISCOVER
    seq: int = 0
    txn: int = 0
    src: int = 0
    dst: int = 0
    group: int = 0
    ts: int = 0
    auth_tag: bytes = b""

    def header(self) -> bytes:
        if not valid_version(self.ver):
            raise ValueError("unsupported protocol major/minor version")
        if self.prof not in (PROF_STD, PROF_RT):
            raise ValueError("unknown profile")
        if self.frame_type not in VALID_TYPES:
            raise ValueError("unknown message TYPE")
        for value, maximum, name in (
            (self.flags, 0xFF, "flags"), (self.seq, 0xFFFF, "seq"),
            (self.txn, 0xFFFF, "txn"), (self.group, 0xFFFF, "group"),
        ):
            if not 0 <= value <= maximum:
                raise ValueError(f"{name} out of range")
        if len(self.payload) > 0xFFFF:
            raise ValueError("payload exceeds LEN")
        fixed = struct.pack(
            ">BBBBHHH", self.ver, self.prof, self.flags, self.frame_type,
            self.seq, self.txn, len(self.payload),
        )
        return SYNC + fixed + _u64(self.src, "src") + _u64(self.dst, "dst") + struct.pack(">H", self.group) + _ts6(self.ts)


def encode_frame(frame: Frame, key: bytes = b"") -> bytes:
    header = frame.header()
    tag = b""
    if frame.flags & AUTH_FLAG:
        if not key:
            raise ValueError("AUTH frame requires a key")
        tag = hmac.new(key, header + frame.payload, hashlib.sha256).digest()[:AUTH_TAG_LEN]
    protected = header + frame.payload + tag
    crc = crc16_ccitt_false(protected).to_bytes(2, "big")
    return protected + crc + TRAILER


@dataclass(frozen=True)
class ParseResult:
    status: str
    frame: Optional[Frame] = None
    detail: str = ""


class StreamParser:
    """Incremental parser; invalid LEN is rejected before payload materialization."""

    def __init__(self, key: bytes = b"", max_payload: int = 0xFFFF,
                 rt_payload_size: Optional[int] = None) -> None:
        self.key = key
        self.max_payload = max_payload
        self.rt_payload_size = rt_payload_size
        self._buffer = bytearray()
        self.payload_materializations = 0

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def _reject_header(self, status: str, results: list[ParseResult], detail: str = "") -> None:
        # A rejected header may be an overlapping SYNC; do not swallow a following valid frame.
        del self._buffer[:1]
        results.append(ParseResult(status, detail=detail))

    def feed(self, data: bytes) -> list[ParseResult]:
        self._buffer.extend(data)
        results: list[ParseResult] = []
        while True:
            start = self._buffer.find(SYNC)
            if start < 0:
                keep = 1 if self._buffer.endswith(b"\xA5") else 0
                if len(self._buffer) > keep:
                    if keep:
                        del self._buffer[:-keep]
                    else:
                        del self._buffer[:]
                    results.append(ParseResult("BAD_SYNC", detail="SYNC not found"))
                break
            if start:
                del self._buffer[:start]
                results.append(ParseResult("BAD_SYNC", detail="garbage before SYNC"))
            if len(self._buffer) < HEADER_LEN:
                results.append(ParseResult("NEED_MORE", detail="partial fixed header"))
                break
            payload_len = int.from_bytes(self._buffer[10:12], "big")
            if payload_len > self.max_payload:
                self._reject_header("BAD_LENGTH", results, f"LEN={payload_len} exceeds {self.max_payload}")
                continue
            version = self._buffer[2]
            profile = self._buffer[3]
            flags = self._buffer[4]
            frame_type = self._buffer[5]
            if not valid_version(version):
                self._reject_header("BAD_VERSION", results, "unsupported major/minor")
                continue
            if profile not in (PROF_STD, PROF_RT):
                self._reject_header("BAD_PROFILE", results)
                continue
            if frame_type not in VALID_TYPES:
                self._reject_header("BAD_TYPE", results)
                continue
            if profile == PROF_RT and self.rt_payload_size is not None and payload_len != self.rt_payload_size:
                self._reject_header("BAD_LENGTH", results, "RT payload is not the configured fixed size")
                continue
            tag_len = AUTH_TAG_LEN if flags & AUTH_FLAG else 0
            total = HEADER_LEN + payload_len + tag_len + 2 + 2
            if len(self._buffer) < total:
                results.append(ParseResult("NEED_MORE", detail="partial frame body"))
                break
            if bytes(self._buffer[total - 2:total]) != TRAILER:
                # total depends on unvalidated LEN; only a successful frame may consume it.
                del self._buffer[:1]
                results.append(ParseResult("BAD_TRAILER"))
                continue
            header = bytes(self._buffer[:HEADER_LEN])
            payload_start = HEADER_LEN
            self.payload_materializations += 1
            payload = bytes(self._buffer[payload_start:payload_start + payload_len])
            tag_start = payload_start + payload_len
            tag = bytes(self._buffer[tag_start:tag_start + tag_len])
            expected_crc = int.from_bytes(self._buffer[tag_start + tag_len:tag_start + tag_len + 2], "big")
            actual_crc = crc16_ccitt_false(header + payload + tag)
            if actual_crc != expected_crc:
                del self._buffer[:1]
                results.append(ParseResult("BAD_CRC"))
                continue
            if flags & AUTH_FLAG:
                expected_tag = hmac.new(self.key, header + payload, hashlib.sha256).digest()[:AUTH_TAG_LEN] if self.key else b""
                if not self.key or not hmac.compare_digest(tag, expected_tag):
                    del self._buffer[:1]
                    results.append(ParseResult("BAD_AUTH"))
                    continue
            del self._buffer[:total]
            frame = Frame(
                payload=payload, ver=header[2], prof=header[3], flags=header[4],
                frame_type=header[5], seq=int.from_bytes(header[6:8], "big"),
                txn=int.from_bytes(header[8:10], "big"), src=int.from_bytes(header[12:20], "big"),
                dst=int.from_bytes(header[20:28], "big"), group=int.from_bytes(header[28:30], "big"),
                ts=int.from_bytes(header[30:36], "big"), auth_tag=tag,
            )
            results.append(ParseResult("OK_RT" if profile == PROF_RT else "OK_STD", frame))
        return results


def encode_tlvs(items: Iterable[tuple[int, bytes]]) -> bytes:
    output = bytearray()
    for tlv_type, value in items:
        if not 0 <= tlv_type <= 0xFF or len(value) > 0xFFFF:
            raise ValueError("invalid TLV")
        output.extend(struct.pack(">BH", tlv_type, len(value)))
        output.extend(value)
    return bytes(output)


def decode_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    output: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 3:
            raise ValueError("truncated TLV header")
        tlv_type = data[offset]
        length = int.from_bytes(data[offset + 1:offset + 3], "big")
        offset += 3
        if len(data) - offset < length:
            raise ValueError("truncated TLV value")
        output.append((tlv_type, data[offset:offset + length]))
        offset += length
    return output


@dataclass
class ScheduledEvent:
    time: float
    sequence: int
    callback: Callable[[], None]
    cancelled: bool = False

    def cancel(self) -> None:
        self.cancelled = True


class EventQueue:
    """Stable (time, insertion sequence) ordering makes simulation deterministic."""

    def __init__(self) -> None:
        self.now = 0.0
        self._sequence = 0
        self._heap: list[tuple[float, int, ScheduledEvent]] = []

    def schedule(self, delay: float, callback: Callable[[], None]) -> ScheduledEvent:
        if delay < 0:
            raise ValueError("cannot schedule in the past")
        event = ScheduledEvent(self.now + delay, self._sequence, callback)
        self._sequence += 1
        heapq.heappush(self._heap, (event.time, event.sequence, event))
        return event

    def run_until(self, end: float) -> None:
        while self._heap and self._heap[0][0] <= end:
            time, _, event = heapq.heappop(self._heap)
            if event.cancelled:
                continue
            self.now = time
            event.callback()
        self.now = max(self.now, end)

    def run_all(self, limit: int = 10000) -> None:
        count = 0
        while self._heap:
            if count >= limit:
                raise RuntimeError("event limit reached")
            self.run_until(self._heap[0][0])
            count += 1


class AnnounceScheduler:
    """The same announce algorithm is used by every role."""

    def __init__(self, events: EventQueue, node_id: int, seed: int,
                 base: float = 1.0, retry_max: float = 30.0,
                 period: float = 10.0, initial_jitter: float = 5.0) -> None:
        self.events = events
        self.node_id = node_id
        self.rng = random.Random(seed)
        self.base = base
        self.retry_max = retry_max
        self.period = period
        self.initial_jitter = initial_jitter
        self.failures = 0
        self.confirmed = False
        self.announcements: list[float] = []
        self.next_delay: Optional[float] = None
        self._pending: Optional[ScheduledEvent] = None

    def start(self) -> None:
        self._schedule(self.rng.uniform(0.0, self.initial_jitter))

    def _schedule(self, delay: float) -> None:
        self.next_delay = delay
        self._pending = self.events.schedule(delay, self._announce)

    def _announce(self) -> None:
        self.announcements.append(self.events.now)
        if self.confirmed:
            self._schedule(self.period)
        else:
            delay = self.rng.uniform(0.0, min(self.base * (2 ** self.failures), self.retry_max))
            self.failures += 1
            self._schedule(delay)

    def confirm(self) -> None:
        self.confirmed = True
        if self._pending is not None:
            self._pending.cancel()
        self._schedule(self.period)


@dataclass(frozen=True)
class Probe:
    originator_id: int
    query_id: int
    hop_limit: int
    query: str = ""
    scope: str = "default"
    target_id: Optional[int] = None
    src_id: Optional[int] = None
    dst_id: Optional[int] = None


@dataclass(frozen=True)
class ProbeResult:
    accepted: bool
    forwarded: Optional[Probe]
    descriptor_loaded: bool
    response_delay: Optional[float] = None
    response_status: str = "E_DUPLICATE"


class DiscoveryAgent:
    """TTL/LRU dedup with non-terminal relay failure and scoped local responses."""

    def __init__(self, cache_capacity: int = 128, cache_ttl: float = 30.0,
                 scope: str = "default", response_rate: float = 1000.0,
                 response_max_jitter: float = 0.0, seed: int = 0,
                 node_id: Optional[int] = None, capability_labels: Sequence[str] = (),
                 model: str = "", vendor: str = "") -> None:
        if cache_capacity < 1 or cache_ttl <= 0 or response_rate <= 0:
            raise ValueError("invalid discovery limits")
        self.cache_capacity = cache_capacity
        self.cache_ttl = cache_ttl
        self.scope = scope
        self.response_interval = 1.0 / response_rate
        self.response_max_jitter = response_max_jitter
        self.rng = random.Random(seed)
        self.node_id = node_id
        self.capability_labels = tuple(capability_labels)
        self.model = model
        self.vendor = vendor
        self._cache: OrderedDict[tuple[int, int], float] = OrderedDict()
        self._response_done: set[tuple[int, int]] = set()
        self._next_response = 0.0
        self.descriptor_fetches = 0

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    @property
    def seen(self) -> set[tuple[int, int]]:
        return set(self._cache)

    def _purge(self, now: float) -> None:
        expired = [key for key, deadline in self._cache.items() if deadline <= now]
        for key in expired:
            del self._cache[key]
            self._response_done.discard(key)

    def _remember(self, key: tuple[int, int], now: float) -> None:
        self._cache[key] = now + self.cache_ttl
        self._cache.move_to_end(key)
        while len(self._cache) > self.cache_capacity:
            old, _ = self._cache.popitem(last=False)
            self._response_done.discard(old)

    def abandon_response(self, originator_id: int, query_id: int) -> None:
        key = (originator_id, query_id)
        self._cache.pop(key, None)
        self._response_done.discard(key)

    def _query_matches(self, query: str) -> bool:
        if not query:
            return True
        haystack = (self.model, self.vendor, *self.capability_labels)
        return any(query in value for value in haystack)

    def receive_probe(self, probe: Probe, descriptor_available: bool = True,
                      now: float = 0.0, forward_ok: bool = True,
                      response_send_ok: bool = True) -> ProbeResult:
        self._purge(now)
        if probe.scope != self.scope:
            return ProbeResult(False, None, False, None, "E_SCOPE")
        key = (probe.originator_id, probe.query_id)
        duplicate = key in self._cache
        forwarded = None
        if duplicate:
            self._cache.move_to_end(key)
        else:
            self._remember(key, now)
            if probe.hop_limit > 0:
                if not forward_ok:
                    self.abandon_response(*key)
                    return ProbeResult(False, None, False, None, "E_SEND")
                forwarded = Probe(probe.originator_id, probe.query_id, probe.hop_limit - 1,
                                  probe.query, probe.scope, probe.target_id,
                                  probe.src_id, probe.dst_id)
        if key in self._response_done:
            return ProbeResult(False, None, False, None, "E_DUPLICATE")
        targeted_elsewhere = probe.target_id is not None and probe.target_id != self.node_id
        if targeted_elsewhere or not self._query_matches(probe.query):
            self._response_done.add(key)
            return ProbeResult(not duplicate, forwarded, False, None,
                               "E_OK" if not duplicate else "E_DUPLICATE")
        if not descriptor_available:
            return ProbeResult(True, forwarded, False, None, "E_UNAVAILABLE")
        self.descriptor_fetches += 1
        if not response_send_ok:
            return ProbeResult(True, forwarded, False, None, "E_SEND")
        start = max(now, self._next_response)
        delay = start - now + self.rng.uniform(0.0, self.response_max_jitter)
        actual_response_time = now + delay
        self._next_response = actual_response_time + self.response_interval
        self._response_done.add(key)
        return ProbeResult(not duplicate, forwarded, True, delay, "E_OK")


class Presence:
    def __init__(self, heartbeat: float, scheduled_period: Optional[float] = None,
                 max_wake_latency: float = 0.0) -> None:
        self.heartbeat = heartbeat
        self.scheduled_period = scheduled_period
        self.max_wake_latency = max_wake_latency
        self.last_valid = 0.0
        self.awake = True
        self.explicit_offline = False

    def receive_valid(self, now: float) -> None:
        self.last_valid = now
        self.awake = True
        self.explicit_offline = False

    def receive_ordinary(self, now: float) -> None:
        # Decodability/authorization is not a resume-from-OFFLINE event.
        self.last_valid = now

    def offline(self) -> None:
        self.explicit_offline = True
        self.awake = False

    def sleep(self) -> None:
        if self.scheduled_period is not None:
            self.awake = False

    def wake(self, now: float) -> str:
        self.receive_valid(now)
        return "CHECK_IN"

    def state(self, now: float) -> str:
        if self.explicit_offline:
            return "OFFLINE"
        elapsed = now - self.last_valid
        if self.scheduled_period is None:
            return "OFFLINE" if elapsed >= 3 * self.heartbeat else "ONLINE"
        upper_bound = max(self.scheduled_period, self.max_wake_latency)
        if elapsed >= upper_bound:
            return "OFFLINE"
        return "ONLINE" if self.awake else "ASLEEP"


@dataclass(frozen=True)
class Grant:
    authority_id: str
    authority_epoch: int
    member_epoch: int
    owner: str
    grant_epoch: int
    token: str
    ttl: float


@dataclass(frozen=True)
class AuthorityProof:
    authority_id: str
    authority_epoch: int
    trusted: bool
    witness_or_config: bool

    def valid(self) -> bool:
        return self.trusted and self.witness_or_config


@dataclass
class MailboxContext:
    binding_id: str
    session_id: str
    executor: "Executor"
    capabilities: frozenset[str] = frozenset({"write"})
    range_min: float = float("-inf")
    range_max: float = float("inf")
    suspended: bool = False
    recovery: bool = False

    def suspend(self) -> None:
        self.suspended = True

    def wake(self) -> None:
        # Waking never revives the old session; a new activation is mandatory.
        self.suspended = True
        self.recovery = True

    def activate(self, binding_id: Optional[str] = None, session_id: Optional[str] = None,
                 executor: Optional["Executor"] = None) -> None:
        if binding_id is not None:
            self.binding_id = binding_id
        if session_id is not None:
            self.session_id = session_id
        if executor is not None:
            self.executor = executor
        self.suspended = False
        self.recovery = False


@dataclass(frozen=True)
class MailboxCommand:
    command_id: str
    not_after: float
    binding_id: str
    session_id: str
    grant: Grant
    payload: str
    value: float = 0.0
    capability: str = "write"


class Mailbox:
    def __init__(self) -> None:
        self.executed: list[str] = []
        self.completed: dict[tuple[str, str, str], tuple[MailboxCommand, str]] = {}

    def deliver(self, command: MailboxCommand, now: float,
                context: MailboxContext, authenticated: bool) -> str:
        if not authenticated:
            return "E_AUTH"
        if context.suspended or context.recovery:
            return "E_SUSPENDED"
        if command.binding_id != context.binding_id:
            return "E_BINDING"
        if command.session_id != context.session_id:
            return "E_SESSION"
        key = (command.binding_id, command.session_id, command.command_id)
        previous = self.completed.get(key)
        if previous is not None:
            return previous[1] if previous[0] == command else "E_COMMAND_CONFLICT"
        if now > command.not_after:
            return "E_EXPIRED"
        if command.capability not in context.capabilities:
            return "E_CAPABILITY"
        if not math.isfinite(command.value):
            return "E_RANGE"
        if not context.range_min <= command.value <= context.range_max:
            return "E_RANGE"
        status = context.executor.validate_write(command.grant, now)
        if status != "E_OK":
            return status
        self.executed.append(command.command_id)
        self.completed[key] = (command, "E_OK")
        return "E_OK"


@dataclass(frozen=True)
class UnitDescriptor:
    unit_id: str
    quantity: str
    value_min: float
    value_max: float
    value_type: str
    permissions: frozenset[str]
    public_complete: bool = True


@dataclass(frozen=True)
class WantDescriptor:
    quantity: str
    required_min: float
    required_max: float
    value_type: str
    required_permissions: frozenset[str]
    public_complete: bool = True


@dataclass(frozen=True)
class MatchResult:
    status: str
    candidates: tuple[str, ...]
    reason: str
    candidate_reasons: Mapping[str, tuple[str, ...]]


def match_units(units: Sequence[UnitDescriptor], want: WantDescriptor) -> MatchResult:
    if not want.public_complete:
        return MatchResult("E_INCOMPLETE", (), "E_INCOMPLETE", {})
    candidates: list[str] = []
    reasons: dict[str, tuple[str, ...]] = {}
    for unit in units:
        failures: list[str] = []
        if not unit.public_complete:
            failures.append("E_INCOMPLETE")
        if unit.quantity != want.quantity:
            failures.append("E_QUANTITY")
        if unit.value_min > want.required_min or unit.value_max < want.required_max:
            failures.append("E_DOMAIN")
        if unit.value_type != want.value_type:
            failures.append("E_TYPE")
        if not want.required_permissions.issubset(unit.permissions):
            failures.append("E_PERMISSION")
        reasons[unit.unit_id] = tuple(failures)
        if not failures:
            candidates.append(unit.unit_id)
    if not candidates:
        return MatchResult("E_NOMATCH", (), "E_UNIT", reasons)
    return MatchResult("E_OK", tuple(candidates), "E_OK", reasons)


@dataclass(frozen=True)
class NegotiationResult:
    status: str
    publication_period: float


def negotiate(producer_period: float, want_period: float,
              link_min: float, stale_after: float) -> NegotiationResult:
    publication = max(producer_period, want_period, link_min)
    return NegotiationResult("E_NEGOTIATE" if publication > stale_after else "E_OK", publication)


def make_schema_id(namespace: int, local_id: int) -> int:
    """u64 schema ID: high 24 bits namespace, low 40 bits namespace-local ID."""
    if not 0 <= namespace <= 0xFFFFFF or not 0 <= local_id <= 0xFFFFFFFFFF:
        raise ValueError("schema namespace must be u24 and local ID must be u40")
    return (namespace << 40) | local_id


@dataclass(frozen=True)
class SchemaField:
    name: str
    value_type: str
    critical: bool = False


@dataclass(frozen=True)
class Schema:
    schema_id: int
    fields: tuple[SchemaField, ...]

    @property
    def digest(self) -> bytes:
        digest = hashlib.sha256()
        for item in self.fields:
            for value in (item.name.encode(), item.value_type.encode(), bytes([item.critical])):
                digest.update(len(value).to_bytes(2, "big"))
                digest.update(value)
        return digest.digest()


def validate_schema(schema: Schema, known_critical: frozenset[str]) -> str:
    unknown = [item.name for item in schema.fields if item.critical and item.name not in known_critical]
    return "E_UNKNOWN_CRITICAL" if unknown else "E_OK"


def check_schema_change(old: Schema, new: Schema, renegotiated: bool,
                        known_critical: frozenset[str]) -> str:
    valid = validate_schema(new, known_critical)
    if valid != "E_OK":
        return valid
    if old.digest == new.digest:
        return "E_OK"
    if old.schema_id == new.schema_id:
        return "E_SCHEMA_ID"
    return "E_OK" if renegotiated else "E_NEGOTIATE"


@dataclass(frozen=True)
class BindingPoint:
    schema_id: int
    ref: str


@dataclass
class Binding:
    binding_id: str
    points: tuple[BindingPoint, ...]
    cap_list: frozenset[str]
    publication_period: float
    active: bool = False


def _proof_field(mac: Any, value: bytes) -> None:
    mac.update(len(value).to_bytes(4, "big"))
    mac.update(value)


def bootstrap_proof(key: bytes, description: bytes, negotiation: bytes,
                    binding_id: str, points: Sequence[BindingPoint],
                    cap_list: frozenset[str], schemas: Mapping[int, Schema],
                    publication_period: float) -> bytes:
    """Authenticate the exact transcript and exact binding preparation inputs."""
    mac = hmac.new(key, digestmod=hashlib.sha256)
    _proof_field(mac, b"ID-CELL-v0.11-bootstrap")
    _proof_field(mac, description)
    _proof_field(mac, negotiation)
    _proof_field(mac, binding_id.encode())
    _proof_field(mac, format(publication_period, ".17g").encode())
    _proof_field(mac, len(points).to_bytes(4, "big"))
    for point in points:
        _proof_field(mac, point.schema_id.to_bytes(8, "big"))
        _proof_field(mac, point.ref.encode())
    _proof_field(mac, len(cap_list).to_bytes(4, "big"))
    for capability in sorted(cap_list):
        _proof_field(mac, capability.encode())
    _proof_field(mac, len(schemas).to_bytes(4, "big"))
    for schema_id, schema in sorted(schemas.items()):
        _proof_field(mac, schema_id.to_bytes(8, "big"))
        _proof_field(mac, schema.schema_id.to_bytes(8, "big"))
        _proof_field(mac, schema.digest)
    return mac.digest()


class BindingManager:
    def __init__(self, bootstrap_key: bytes) -> None:
        self.bootstrap_key = bootstrap_key
        self.bindings: dict[str, Binding] = {}

    def prepare(self, binding_id: str, points: Sequence[BindingPoint],
                cap_list: frozenset[str], schemas: Mapping[int, Schema],
                known_critical: frozenset[str], authenticated: bool,
                authorized_view_verified: bool, description: bytes,
                negotiation: bytes, proof: bytes, publication_period: float = 0.0) -> str:
        if not authenticated:
            return "E_AUTH"
        if not authorized_view_verified:
            return "E_VIEW"
        expected = bootstrap_proof(
            self.bootstrap_key, description, negotiation, binding_id, points,
            cap_list, schemas, publication_period,
        )
        if not hmac.compare_digest(expected, proof):
            return "E_BOOTSTRAP"
        for point in points:
            schema = schemas.get(point.schema_id)
            if schema is None or schema.schema_id != point.schema_id:
                return "E_SCHEMA"
            valid = validate_schema(schema, known_critical)
            if valid != "E_OK":
                return valid
        self.bindings[binding_id] = Binding(binding_id, tuple(points), cap_list, publication_period, False)
        return "E_OK"

    def commit(self, binding_id: str) -> str:
        binding = self.bindings.get(binding_id)
        if binding is None or binding.active:
            return "E_NO_PREPARED"
        binding.active = True
        return "E_OK"

    def abort(self, binding_id: str) -> None:
        binding = self.bindings.get(binding_id)
        if binding is not None and not binding.active:
            del self.bindings[binding_id]

    def unbind(self, binding_id: str) -> None:
        self.bindings.pop(binding_id, None)

    def visible(self, binding_id: str) -> bool:
        binding = self.bindings.get(binding_id)
        return bool(binding and binding.active)

    def access(self, binding_id: str, capability: str) -> str:
        binding = self.bindings.get(binding_id)
        if binding is None or not binding.active:
            return "E_NO_ACTIVE_BIND"
        return "E_OK" if capability in binding.cap_list else "E_CAPABILITY"


@dataclass
class CapabilityPoint:
    ref: str
    schema_id: int
    range_min: float
    range_max: float
    value: float = 0.0
    executor_key: str = "default"


class Provider:
    """Shared points with contract-scoped visibility and per-point executor fencing."""

    def __init__(self, executor: "Executor", points: Sequence[CapabilityPoint],
                 executors: Optional[Mapping[str, "Executor"]] = None) -> None:
        self.executor = executor
        self.executors = {"default": executor}
        if executors:
            self.executors.update(executors)
        self.points = {point.ref: point for point in points}

    def read(self, ref: str, capabilities: frozenset[str]) -> tuple[str, Optional[float]]:
        point = self.points.get(ref)
        if point is None:
            return "E_NO_POINT", None
        if "read" not in capabilities:
            return "E_CAPABILITY", None
        return "E_OK", point.value

    def write(self, ref: str, value: float, grant: Grant, now: float,
              capabilities: frozenset[str]) -> str:
        point = self.points.get(ref)
        if point is None:
            return "E_NO_POINT"
        if "write" not in capabilities:
            return "E_CAPABILITY"
        if not point.range_min <= value <= point.range_max:
            return "E_RANGE"
        point_executor = self.executors.get(point.executor_key)
        if point_executor is None:
            return "E_NO_EXECUTOR"
        status = point_executor.validate_write(grant, now)
        if status == "E_OK":
            point.value = value
        return status


@dataclass
class Controller:
    controller_id: str
    bindings: BindingManager
    provider: Optional[Provider] = None
    online: bool = True

    def access(self, binding_id: str, capability: str) -> str:
        if not self.online:
            return "E_OFFLINE"
        return self.bindings.access(binding_id, capability)

    def unbind(self, binding_id: str) -> None:
        self.bindings.unbind(binding_id)

    def read(self, binding_id: str, ref: str) -> tuple[str, Optional[float]]:
        if not self.online or self.provider is None:
            return "E_OFFLINE", None
        binding = self.bindings.bindings.get(binding_id)
        if binding is None or not binding.active:
            return "E_NO_ACTIVE_BIND", None
        if ref not in {point.ref for point in binding.points}:
            return "E_CAPABILITY", None
        return self.provider.read(ref, binding.cap_list)

    def write(self, binding_id: str, ref: str, value: float,
              grant: Grant, now: float) -> str:
        if not self.online or self.provider is None:
            return "E_OFFLINE"
        binding = self.bindings.bindings.get(binding_id)
        if binding is None or not binding.active:
            return "E_NO_ACTIVE_BIND"
        if ref not in {point.ref for point in binding.points}:
            return "E_CAPABILITY"
        return self.provider.write(ref, value, grant, now, binding.cap_list)


@dataclass(frozen=True)
class RoutedFrame:
    wire: bytes
    hop_limit: int


def relay_frame(routed: RoutedFrame, tamper_payload: bool = False) -> Optional[RoutedFrame]:
    """A relay has no endpoint key and forwards raw wire bytes unchanged."""
    if routed.hop_limit <= 0:
        return None
    wire = routed.wire
    if tamper_payload:
        if len(wire) < HEADER_LEN + 4:
            raise ValueError("short wire frame")
        payload_len = int.from_bytes(wire[10:12], "big")
        if payload_len == 0:
            raise ValueError("cannot tamper an empty payload")
        mutable = bytearray(wire)
        mutable[HEADER_LEN] ^= 1
        tag_len = AUTH_TAG_LEN if mutable[4] & AUTH_FLAG else 0
        crc_offset = HEADER_LEN + payload_len + tag_len
        crc = crc16_ccitt_false(bytes(mutable[:crc_offset])).to_bytes(2, "big")
        mutable[crc_offset:crc_offset + 2] = crc
        wire = bytes(mutable)
    return RoutedFrame(wire, routed.hop_limit - 1)


class FrameDeduplicator:
    """Bounded TTL/LRU wire-frame dedup for loops and multiple paths."""

    def __init__(self, capacity: int = 256, ttl: float = 30.0) -> None:
        if capacity < 1 or ttl <= 0:
            raise ValueError("invalid frame dedup limits")
        self.capacity = capacity
        self.ttl = ttl
        self._cache: OrderedDict[bytes, float] = OrderedDict()
        self.processed = 0

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    def accept(self, wire: bytes, now: float = 0.0) -> bool:
        expired = [key for key, deadline in self._cache.items() if deadline <= now]
        for key in expired:
            del self._cache[key]
        key = hashlib.sha256(wire).digest()
        if key in self._cache:
            self._cache.move_to_end(key)
            return False
        self._cache[key] = now + self.ttl
        while len(self._cache) > self.capacity:
            self._cache.popitem(last=False)
        self.processed += 1
        return True


class Executor:
    """Lease executor with fingerprint, epoch, release and restart fencing."""

    def __init__(self, member_id: str, storage: Optional[dict[str, object]] = None) -> None:
        self.member_id = member_id
        self.storage = storage if storage is not None else {}
        self.trusted_authority_id = str(self.storage.get("authority_id", ""))
        self.trusted_authority_epoch = int(self.storage.get("authority_epoch", 0))
        self.authority_id = self.trusted_authority_id
        self.authority_epoch = self.trusted_authority_epoch
        self.member_epoch = int(self.storage.get("member_epoch", 0))
        self.grant_epoch_floor = int(self.storage.get("grant_epoch", 0))
        fingerprints = self.storage.setdefault("grant_fingerprints", {})
        if not isinstance(fingerprints, dict):
            raise ValueError("invalid persisted grant fingerprints")
        self.fingerprints = cast(dict[int, Grant], fingerprints)
        self.active_grant: Optional[Grant] = None
        self.active_deadline = 0.0
        self.activation_confirmed = False
        self.pending_grant: Optional[Grant] = None
        self.old_released = False
        self.writes: list[str] = []

    def _persist(self, grant: Grant) -> None:
        self.grant_epoch_floor = max(self.grant_epoch_floor, grant.grant_epoch)
        self.fingerprints[grant.grant_epoch] = grant
        self.trusted_authority_id = grant.authority_id
        self.trusted_authority_epoch = grant.authority_epoch
        self.storage.update(
            authority_id=grant.authority_id,
            authority_epoch=max(grant.authority_epoch, int(self.storage.get("authority_epoch", 0))),
            member_epoch=max(grant.member_epoch, int(self.storage.get("member_epoch", 0))),
            grant_epoch=self.grant_epoch_floor,
        )

    def _switch_proof_ok(self, grant: Grant, proof: Optional[AuthorityProof]) -> bool:
        if not self.trusted_authority_id:
            return True
        switching = grant.authority_id != self.trusted_authority_id or grant.authority_epoch > self.trusted_authority_epoch
        if not switching:
            return True
        return bool(
            grant.authority_epoch > self.trusted_authority_epoch and proof and proof.valid()
            and proof.authority_id == grant.authority_id
            and proof.authority_epoch == grant.authority_epoch
        )

    def offer_grant(self, grant: Grant, now: float,
                    proof: Optional[AuthorityProof] = None) -> str:
        known = self.fingerprints.get(grant.grant_epoch)
        if known is not None and known != grant:
            return "E_GRANT_CONFLICT"
        if self.active_grant == grant:
            if self.old_released:
                return "E_RELEASED"
            if now >= self.active_deadline:
                return "E_EXPIRED"
            return "E_OK" if self.activation_confirmed else "E_PENDING_ACK"
        if self.pending_grant == grant:
            return "E_WAIT_RELEASE"
        if grant.grant_epoch <= self.grant_epoch_floor:
            return "E_STALE_EPOCH"
        if grant.authority_epoch < int(self.storage.get("authority_epoch", 0)) or grant.member_epoch < int(self.storage.get("member_epoch", 0)):
            return "E_STALE_EPOCH"
        if grant.ttl <= 0:
            return "E_EXPIRED"
        if not self._switch_proof_ok(grant, proof):
            return "E_UNTRUSTED_AUTHORITY"
        self._persist(grant)
        if self.active_grant is not None and not self.old_released and now < self.active_deadline:
            self.pending_grant = grant
            return "E_WAIT_RELEASE"
        if self.active_grant is not None:
            self.pending_grant = grant
            return self.activate_pending(now)
        self.active_grant = grant
        self.active_deadline = now + grant.ttl
        self.activation_confirmed = False
        self.authority_id = grant.authority_id
        self.authority_epoch = grant.authority_epoch
        self.member_epoch = grant.member_epoch
        return "E_PENDING_ACK"

    def confirm_release(self, owner: str, token: str, now: float) -> str:
        if self.active_grant is None or self.active_grant.owner != owner or self.active_grant.token != token:
            return "E_FENCING"
        if self.old_released:
            return "E_OK"
        self.old_released = True
        if self.pending_grant is not None:
            return self.activate_pending(now)
        return "E_OK"

    def activate_pending(self, now: float) -> str:
        if self.pending_grant is None:
            return "E_NO_PENDING"
        if self.active_grant is not None and not self.old_released and now < self.active_deadline:
            return "E_WAIT_RELEASE"
        grant = self.pending_grant
        self.pending_grant = None
        self.active_grant = grant
        self.active_deadline = now + grant.ttl
        self.activation_confirmed = False
        self.old_released = False
        self.authority_id = grant.authority_id
        self.authority_epoch = grant.authority_epoch
        self.member_epoch = grant.member_epoch
        return "E_PENDING_ACK"

    def confirm_activation(self, token: str, now: float) -> str:
        if self.active_grant is None or self.active_grant.token != token or self.old_released or now >= self.active_deadline:
            return "E_FENCING"
        self.activation_confirmed = True
        return "E_OK"

    def validate_write(self, grant: Grant, now: float) -> str:
        current = self.active_grant
        if current is not None and grant != current:
            return "E_FENCING"
        if current is None or not self.activation_confirmed:
            return "E_NOT_ACTIVE"
        if self.old_released:
            return "E_FENCING"
        if now >= self.active_deadline:
            return "E_EXPIRED"
        if grant.authority_id != self.authority_id or grant.authority_epoch != self.authority_epoch or grant.member_epoch != self.member_epoch:
            return "E_FENCING"
        return "E_OK"

    def write(self, grant: Grant, now: float, value: str) -> str:
        status = self.validate_write(grant, now)
        if status == "E_OK":
            self.writes.append(value)
        return status

    def restart(self) -> None:
        self.active_grant = None
        self.pending_grant = None
        self.active_deadline = 0.0
        self.activation_confirmed = False
        self.old_released = False
        self.authority_id = self.trusted_authority_id
        self.authority_epoch = self.trusted_authority_epoch
