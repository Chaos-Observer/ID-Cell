from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Callable

from idcell_sim import (
    AUTH_FLAG, HEADER_LEN, PROF_RT, PROF_STD, PROTOCOL_VERSION, TYPE_DISCOVER, TYPE_READ,
    TYPE_WRITE, VERSION, AnnounceScheduler, AuthorityProof, BindingManager, BindingPoint,
    CapabilityPoint, Controller, DiscoveryAgent, EventQueue, Executor, Frame,
    FrameDeduplicator, Grant, Mailbox, MailboxCommand, MailboxContext, Presence,
    Probe, Provider, RoutedFrame, Schema, SchemaField, StreamParser,
    UnitDescriptor, WantDescriptor, bootstrap_proof, check_schema_change,
    encode_frame, encode_tlvs, make_schema_id, match_units, negotiate,
    relay_frame,
)

SEED = 11
KEY = b"scenario-end-to-end-key"
GOLDEN_KEY = b"golden-key"
GOLDEN_NOAUTH = bytes.fromhex(
    "a5a50b00000801020304000301020304050607081112131415161718"
    "191a1b1c1d1e1f204142430ae95aa5"
)
GOLDEN_AUTH = bytes.fromhex(
    "a5a50b00200921222324000331323334353637384142434445464748"
    "495051525354555658595a536fa86bb6e59c593874eb0d0e34a95517fa5aa5"
)
Scenario = Callable[[], dict[str, object]]


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def independent_crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def recrc(wire: bytes) -> bytes:
    mutable = bytearray(wire)
    payload_len = int.from_bytes(mutable[10:12], "big")
    tag_len = 16 if mutable[4] & AUTH_FLAG else 0
    crc_at = HEADER_LEN + payload_len + tag_len
    mutable[crc_at:crc_at + 2] = independent_crc16(bytes(mutable[:crc_at])).to_bytes(2, "big")
    return bytes(mutable)


def frame(payload: bytes = b"data", flags: int = 0, prof: int = PROF_STD,
          frame_type: int = TYPE_DISCOVER, ver: int = VERSION) -> Frame:
    return Frame(payload=payload, flags=flags, prof=prof, frame_type=frame_type,
                 ver=ver, seq=1, txn=2, src=10, dst=20, group=4, ts=123456)


def golden_frame(authenticated: bool) -> Frame:
    if not authenticated:
        return Frame(payload=b"ABC", frame_type=TYPE_READ, seq=0x0102, txn=0x0304,
                     src=0x0102030405060708, dst=0x1112131415161718,
                     group=0x191A, ts=0x1B1C1D1E1F20)
    return Frame(payload=b"XYZ", flags=AUTH_FLAG, frame_type=TYPE_WRITE,
                 seq=0x2122, txn=0x2324, src=0x3132333435363738,
                 dst=0x4142434445464748, group=0x4950, ts=0x515253545556)


def grant(owner: str = "a", token: str = "ta", grant_epoch: int = 1,
          authority_id: str = "auth-a", authority_epoch: int = 1,
          member_epoch: int = 1, ttl: float = 10) -> Grant:
    return Grant(authority_id, authority_epoch, member_epoch, owner,
                 grant_epoch, token, ttl)


def active_executor(selected: Grant | None = None,
                    storage: dict[str, object] | None = None) -> Executor:
    executor = Executor("member", storage)
    current = selected or grant()
    check(executor.offer_grant(current, 0) == "E_PENDING_ACK", "initial grant not offered")
    check(executor.confirm_activation(current.token, 0) == "E_OK", "initial grant not activated")
    return executor


def binding_manager(binding_id: str = "binding",
                    capabilities: frozenset[str] = frozenset({"read"}),
                    period: float = 5) -> BindingManager:
    manager = BindingManager(KEY)
    description, negotiation_result = b"public-description", b"T_pub=5"
    current = Schema(1, (SchemaField("value", "f64", True),))
    points = [BindingPoint(1, "point")]
    schemas = {1: current}
    proof = bootstrap_proof(KEY, description, negotiation_result, binding_id,
                            points, capabilities, schemas, period)
    status = manager.prepare(
        binding_id, points, capabilities, schemas, frozenset({"value"}), True, True,
        description, negotiation_result, proof, period,
    )
    check(status == "E_OK", f"prepare failed: {status}")
    return manager


def discovery_announce_schedule() -> dict[str, object]:
    events = EventQueue()
    announce = AnnounceScheduler(events, 1, SEED, base=1, retry_max=4, period=10)
    announce.start()
    first_delay = announce.next_delay
    events.run_until(100)
    check(announce.failures >= 3 and announce.next_delay <= 4, "retry cap failed")
    announce.confirm()
    events.run_until(events.now + 50)
    intervals = [round(b - a, 6) for a, b in zip(announce.announcements, announce.announcements[1:])]
    check(intervals[-3:] == [10.0, 10.0, 10.0], "confirmed announce is not periodic")
    return {"initial_delay": first_delay, "announcements": len(announce.announcements), "confirmed_interval": 10}


def discovery_probe_dedup_forward() -> dict[str, object]:
    agent = DiscoveryAgent()
    first = agent.receive_probe(Probe(1, 7, 2))
    duplicate = agent.receive_probe(Probe(1, 7, 2))
    other_origin = agent.receive_probe(Probe(2, 7, 2))
    check(first.accepted and not duplicate.accepted and other_origin.accepted, "originator-scoped dedup failed")
    check(agent.descriptor_fetches == 2 and first.forwarded.hop_limit == 1, "dedup/forward failed")
    terminal = DiscoveryAgent().receive_probe(Probe(1, 7, 0))
    check(terminal.forwarded is None, "zero-hop probe forwarded")
    relay = DiscoveryAgent(node_id=99)
    routed = Probe(3, 8, 2, target_id=20, src_id=10, dst_id=20)
    failed = relay.receive_probe(routed, descriptor_available=False, forward_ok=False)
    check(failed.response_status == "E_SEND" and relay.cache_size == 0, "forward fault left terminal dedup")
    forwarded = relay.receive_probe(routed, descriptor_available=False).forwarded
    check((forwarded.src_id, forwarded.dst_id) == (10, 20), "relay rewrote end-to-end endpoints")
    return {"descriptor_fetches": agent.descriptor_fetches, "forwarded_hop": first.forwarded.hop_limit,
            "relay_src": forwarded.src_id, "relay_dst": forwarded.dst_id, "send_fault": failed.response_status}


def frame_std_rt_roundtrip() -> dict[str, object]:
    std = frame(encode_tlvs([(1, b"abc"), (2, b"def")]), frame_type=TYPE_READ)
    rt = frame(b"\x00\x01\xFF", prof=PROF_RT, frame_type=TYPE_READ)
    results = StreamParser(rt_payload_size=3).feed(encode_frame(std) + encode_frame(rt))
    check([item.status for item in results] == ["OK_STD", "OK_RT"], "STD/RT roundtrip failed")
    check(results[0].frame.src == 10 and results[1].frame.payload.endswith(b"\xFF"), "frame fields changed")
    return {"statuses": [item.status for item in results], "header_bytes": len(std.header())}


def frame_stream_resilience() -> dict[str, object]:
    wire = encode_frame(frame(b"one")) + encode_frame(frame(b"two"))
    for split in range(len(wire) + 1):
        parser = StreamParser()
        results = parser.feed(wire[:split]) + parser.feed(wire[split:])
        payloads = [item.frame.payload for item in results if item.frame]
        check(payloads == [b"one", b"two"], f"split {split} lost a frame")
    oversized_parser = StreamParser(max_payload=2)
    oversized = oversized_parser.feed(encode_frame(frame(b"too-long")))
    check(oversized[0].status == "BAD_LENGTH", "bad LEN accepted")
    check(oversized_parser.payload_materializations == 0, "oversize payload materialized")
    first = bytearray(encode_frame(frame(b"abc")))
    second = encode_frame(frame(b"12345"))
    check((len(first), len(second)) == (43, 45), "regression vector lengths changed")
    first[10:12] = (48).to_bytes(2, "big")
    recovered = StreamParser().feed(bytes(first) + second)
    payloads = [item.frame.payload for item in recovered if item.frame]
    check(recovered[0].status == "BAD_CRC" and payloads == [b"12345"], "bad LEN dropped next frame")
    return {"splits_checked": len(wire) + 1, "oversize_status": oversized[0].status,
            "payload_materializations": 0,
            "bad_len_recovery": [payload.decode("ascii") for payload in payloads]}


def frame_auth_crc_errors() -> dict[str, object]:
    authenticated = frame(b"secret", AUTH_FLAG)
    good = StreamParser(KEY).feed(encode_frame(authenticated, KEY))
    bad_auth = StreamParser(KEY).feed(encode_frame(authenticated, b"wrong"))
    corrupted = bytearray(encode_frame(frame()))
    corrupted[36] ^= 1
    bad_crc = StreamParser().feed(bytes(corrupted))
    check(good[0].status == "OK_STD", "valid AUTH rejected")
    check(bad_auth[0].status == "BAD_AUTH" and bad_crc[0].status == "BAD_CRC", "tamper accepted")
    return {"valid": good[0].status, "tampered_auth": bad_auth[0].status, "tampered_crc": bad_crc[0].status}


def sleep_deadlines() -> dict[str, object]:
    ordinary = Presence(5)
    scheduled = Presence(5, scheduled_period=20, max_wake_latency=30)
    scheduled.sleep()
    check(ordinary.state(14.9) == "ONLINE" and ordinary.state(15) == "OFFLINE", "ordinary deadline failed")
    check(scheduled.state(29.9) == "ASLEEP" and scheduled.state(30) == "OFFLINE", "scheduled upper bound failed")
    check(scheduled.wake(31) == "CHECK_IN" and scheduled.state(31) == "ONLINE", "wake check-in failed")
    scheduled.sleep()
    scheduled.receive_valid(40)
    check(scheduled.state(40) == "ONLINE", "valid scheduled frame did not wake")
    scheduled.offline()
    scheduled.receive_ordinary(41)
    check(scheduled.state(41) == "OFFLINE", "ordinary frame cleared explicit OFFLINE")
    scheduled.receive_valid(42)
    check(scheduled.state(42) == "ONLINE", "CHECK-IN/HELLO did not resume OFFLINE")
    return {"ordinary_offline_at": 15, "scheduled_offline_at": 30, "wake_action": "CHECK_IN", "receive_valid": "ONLINE",
            "ordinary_after_offline": "OFFLINE", "checkin_resume": "ONLINE"}


def sleep_mailbox_reauth() -> dict[str, object]:
    executor = active_executor()
    mailbox = Mailbox()
    context = MailboxContext("binding", "session", executor)
    command = MailboxCommand("command", 5, "binding", "session", grant(), "write")
    check(mailbox.deliver(command, 1, context, True) == "E_OK", "valid mailbox command rejected")
    expired = MailboxCommand("expired", 5, "binding", "session", grant(), "write")
    check(mailbox.deliver(expired, 6, context, True) == "E_EXPIRED", "expired command executed")
    unauthenticated = MailboxCommand("unauth", 5, "binding", "session", grant(), "write")
    check(mailbox.deliver(unauthenticated, 1, context, False) == "E_AUTH", "unauthenticated command accepted")
    stale = MailboxCommand("stale", 9, "binding", "old-session", grant(), "write")
    check(mailbox.deliver(stale, 1, context, True) == "E_SESSION", "old session executed")
    context.suspend()
    check(mailbox.deliver(command, 2, context, True) == "E_SUSPENDED", "suspended contract executed")
    context.wake()
    check(mailbox.deliver(command, 3, context, True) == "E_SUSPENDED", "wake revived old context")
    context.activate("new-binding", "new-session", active_executor())
    check(mailbox.deliver(command, 4, context, True) == "E_BINDING", "old context executed after new activation")
    nan = MailboxCommand("nan", 9, "new-binding", "new-session", grant(), "write", float("nan"))
    check(mailbox.deliver(nan, 4, context, True) == "E_RANGE", "NaN executed")
    return {"executed": mailbox.executed, "expired": "E_EXPIRED", "old_session": "E_SESSION",
            "suspended": "E_SUSPENDED", "new_context_old": "E_BINDING", "nan": "E_RANGE"}


def contract_match_constraints() -> dict[str, object]:
    units = [
        UnitDescriptor("a", "temperature", -10, 50, "f64", frozenset({"read"})),
        UnitDescriptor("b", "temperature", -20, 60, "f64", frozenset({"read", "write"})),
        UnitDescriptor("bad", "temperature", 0, 10, "i16", frozenset()),
    ]
    want = WantDescriptor("temperature", 0, 40, "f64", frozenset({"read"}))
    result = match_units(units, want)
    check(result.candidates == ("a", "b"), "not all candidates returned")
    check(result.candidate_reasons["bad"] == ("E_DOMAIN", "E_TYPE", "E_PERMISSION"), "hard constraint reasons missing")
    no_match = match_units(units[:1], WantDescriptor("humidity", 0, 1, "f64", frozenset()))
    check(no_match.status == "E_NOMATCH" and no_match.reason == "E_UNIT", "E_NOMATCH/E_UNIT missing")
    return {"candidates": result.candidates, "rejected_reasons": result.candidate_reasons["bad"]}


def contract_negotiate_bind_lifecycle() -> dict[str, object]:
    accepted = negotiate(3, 5, 4, 6)
    stale = negotiate(3, 5, 7, 6)
    check((accepted.status, accepted.publication_period) == ("E_OK", 5), "T_pub max rule failed")
    check(stale.status == "E_NEGOTIATE", "stale negotiation accepted")
    manager = binding_manager()
    check(not manager.visible("binding"), "prepared binding became visible")
    check(manager.commit("binding") == "E_OK" and manager.access("binding", "read") == "E_OK", "commit did not activate")
    check(manager.access("binding", "write") == "E_CAPABILITY", "cap_list escape")
    aborted = binding_manager()
    aborted.abort("binding")
    check("binding" not in aborted.bindings, "abort left residue")
    return {"T_pub": accepted.publication_period, "stale_status": stale.status, "capability_violation": "E_CAPABILITY"}


def schema_namespace_change() -> dict[str, object]:
    schema_id = make_schema_id(7, 9)
    check(schema_id == (7 << 40) | 9 and schema_id < 2 ** 64, "u24/u40 namespace model failed")
    check(make_schema_id(0xFFFFFF, 0xFFFFFFFFFF) == 0xFFFFFFFFFFFFFFFF, "schema boundary failed")
    old = Schema(schema_id, (SchemaField("value", "f64", True),))
    changed = Schema(make_schema_id(7, 10), (SchemaField("value", "i16", True),))
    check(check_schema_change(old, changed, False, frozenset({"value"})) == "E_NEGOTIATE", "structure change skipped negotiation")
    check(check_schema_change(old, changed, True, frozenset({"value"})) == "E_OK", "valid new schema rejected")
    unknown = Schema(make_schema_id(7, 11), (SchemaField("unknown", "u8", True),))
    check(check_schema_change(old, unknown, True, frozenset({"value"})) == "E_UNKNOWN_CRITICAL", "unknown critical accepted")
    return {"schema_id": schema_id, "new_schema_id": changed.schema_id, "unknown_critical": "E_UNKNOWN_CRITICAL"}


def distributed_controller_isolation() -> dict[str, object]:
    executor = active_executor()
    provider = Provider(executor, [CapabilityPoint("point", 1, 0, 100), CapabilityPoint("other", 1, 0, 100)])
    one = Controller("one", binding_manager("one", frozenset({"read", "write"}), 5), provider)
    two = Controller("two", binding_manager("two", frozenset({"read"}), 12), provider)
    one.bindings.commit("one")
    two.bindings.commit("two")
    check(one.bindings.bindings["one"].publication_period == 5, "first period missing")
    check(two.bindings.bindings["two"].publication_period == 12, "second period missing")
    check(one.write("one", "point", 42, grant(), 1) == "E_OK", "shared provider write failed")
    check(two.read("two", "point") == ("E_OK", 42), "shared point not visible")
    check(two.write("two", "point", 43, grant(), 1) == "E_CAPABILITY", "permission isolation failed")
    check(one.write("one", "other", 44, grant(), 1) == "E_CAPABILITY", "contract point escape succeeded")
    check(provider.points["other"].value == 0, "contract-external point changed")
    one.online = False
    one.unbind("one")
    check(one.access("one", "read") == "E_OFFLINE", "offline controller accessed")
    check(two.read("two", "point") == ("E_OK", 42), "second controller affected")
    return {"controller_one": "E_OFFLINE", "controller_two": "E_OK", "shared_value": 42, "periods": [5, 12], "outside_contract": "E_CAPABILITY"}


def distributed_relay_loop_tamper() -> dict[str, object]:
    wire = encode_frame(frame(b"session=4;binding=8", AUTH_FLAG), KEY)
    relayed = relay_frame(RoutedFrame(wire, 2))
    check(relayed.wire == wire, "keyless relay changed wire")
    second = relay_frame(relayed)
    check(second.hop_limit == 0 and relay_frame(second) is None, "loop did not terminate")
    check(StreamParser(KEY).feed(relayed.wire)[0].status == "OK_STD", "normal relay failed")
    tampered = relay_frame(RoutedFrame(wire, 2), tamper_payload=True)
    status = StreamParser(KEY).feed(tampered.wire)[0].status
    check(status == "BAD_AUTH", "relay tampering escaped HMAC")
    return {"terminal_hop_limit": second.hop_limit, "normal": "OK_STD", "tamper_status": status}


def security_handover_release() -> dict[str, object]:
    old = grant()
    executor = active_executor(old)
    new = grant("b", "tb", 2)
    check(executor.offer_grant(new, 1) == "E_WAIT_RELEASE", "new owner activated before release")
    check(executor.write(old, 1, "old") == "E_OK", "old valid owner interrupted early")
    check(executor.confirm_release(old.owner, old.token, 2) == "E_PENDING_ACK", "release did not activate pending grant")
    check(executor.write(new, 2, "early") == "E_NOT_ACTIVE", "new owner wrote before activation ack")
    check(executor.confirm_activation(new.token, 2) == "E_OK", "activation ack rejected")
    check(executor.write(new, 2, "new") == "E_OK", "activated owner cannot write")
    return {"handover": "release", "pre_ack": "E_NOT_ACTIVE", "post_ack": "E_OK"}


def security_handover_ttl() -> dict[str, object]:
    executor = active_executor(grant())
    new = grant("b", "tb", 2)
    check(executor.offer_grant(new, 1) == "E_WAIT_RELEASE", "grant did not wait")
    check(executor.activate_pending(9.9) == "E_WAIT_RELEASE", "grant activated before old TTL")
    check(executor.activate_pending(10) == "E_PENDING_ACK", "grant did not activate at old TTL")
    return {"old_deadline": 10, "activation": "E_PENDING_ACK"}


def security_authority_proof() -> dict[str, object]:
    executor = active_executor(grant())
    contender = grant("b", "tb", 2, "auth-b", 2)
    check(executor.offer_grant(contender, 1) == "E_UNTRUSTED_AUTHORITY", "unwitnessed dual leader accepted")
    proof = AuthorityProof("auth-b", 2, True, True)
    check(executor.offer_grant(contender, 1, proof) == "E_WAIT_RELEASE", "witnessed higher epoch rejected")
    return {"without_proof": "E_UNTRUSTED_AUTHORITY", "with_proof": "E_WAIT_RELEASE"}


def security_restart_fence() -> dict[str, object]:
    storage: dict[str, object] = {}
    old = grant()
    executor = active_executor(old, storage)
    second = grant("b", "tb", 2)
    check(executor.offer_grant(second, 1) == "E_WAIT_RELEASE", "new grant not pending")
    executor.restart()
    restarted = Executor("member", storage)
    check(restarted.write(old, 1, "stale") == "E_NOT_ACTIVE", "old token survived restart")
    check(restarted.offer_grant(second, 2) == "E_STALE_EPOCH", "used grant reactivated after restart")
    third = grant("c", "tc", 3)
    check(restarted.offer_grant(third, 2) == "E_PENDING_ACK", "higher grant cannot reactivate")
    check(restarted.confirm_activation(third.token, 2) == "E_OK", "reactivation ack failed")
    check(restarted.write(third, 2, "valid") == "E_OK", "reactivated writer rejected")
    return {"persisted_grant_epoch": storage["grant_epoch"], "old_write": "E_NOT_ACTIVE", "new_write": "E_OK"}


def frame_golden_vectors_and_tamper() -> dict[str, object]:
    check(encode_frame(golden_frame(False)) == GOLDEN_NOAUTH, "no-AUTH golden mismatch")
    check(encode_frame(golden_frame(True), GOLDEN_KEY) == GOLDEN_AUTH, "AUTH golden mismatch")
    statuses = []
    for offset in (6, 12, 20, 30, 39):
        mutable = bytearray(GOLDEN_AUTH)
        mutable[offset] ^= 1
        status = StreamParser(GOLDEN_KEY).feed(recrc(bytes(mutable)))[0].status
        statuses.append(status)
    check(statuses == ["BAD_AUTH"] * 5, "header/tag tamper escaped")
    return {"golden_vectors": 2, "tamper_offsets": [6, 12, 20, 30, 39], "statuses": statuses}


def frame_version_type_profile_negative() -> dict[str, object]:
    statuses = []
    for offset, value in ((2, 0x1B), (3, 2), (5, 0xFF)):
        mutable = bytearray(encode_frame(frame()))
        mutable[offset] = value
        statuses.append(StreamParser().feed(recrc(bytes(mutable)))[0].status)
    check(statuses == ["BAD_VERSION", "BAD_PROFILE", "BAD_TYPE"], "header validation failed")
    compatible = StreamParser().feed(encode_frame(frame(ver=VERSION + 1)))[0]
    check(compatible.status == "OK_STD" and compatible.frame.ver == VERSION + 1, "compatible minor rejected")
    semantic_rt = encode_frame(frame(b"rt", prof=PROF_RT, frame_type=TYPE_READ))
    check(StreamParser(rt_payload_size=2).feed(semantic_rt)[0].status == "OK_RT", "TYPE selected profile")
    return {"statuses": statuses, "compatible_minor": compatible.status, "rt_type": "READ", "rt_profile": "PROF_RT"}


def discovery_recovery_cache_scope_rate() -> dict[str, object]:
    agent = DiscoveryAgent(cache_capacity=2, cache_ttl=5, scope="a", response_rate=2, response_max_jitter=0.2, seed=SEED)
    failed = agent.receive_probe(Probe(1, 1, 1, scope="a"), False, 0)
    recovered = agent.receive_probe(Probe(1, 1, 1, scope="a"), True, 0)
    check(failed.response_status == "E_UNAVAILABLE" and recovered.descriptor_loaded, "failure suppressed recovery")
    duplicate = agent.receive_probe(Probe(1, 1, 0, scope="a"), True, 1)
    check(not duplicate.accepted, "dual-path duplicate processed")
    outside = agent.receive_probe(Probe(2, 1, 3, scope="b"), True, 1)
    check(outside.forwarded is None, "scope escape forwarded")
    check(not outside.accepted and not outside.descriptor_loaded and outside.response_status == "E_SCOPE", "scope escape processed locally")
    agent.receive_probe(Probe(3, 1, 0, scope="a"), True, 1)
    agent.receive_probe(Probe(4, 1, 0, scope="a"), True, 1)
    check(agent.cache_size == 2, "cache capacity exceeded")
    check(agent.receive_probe(Probe(1, 1, 0, scope="a"), True, 6).accepted, "TTL retry failed")
    check(recovered.response_delay <= 0.2, "seeded jitter out of range")
    paced = DiscoveryAgent(response_rate=2, response_max_jitter=1, seed=0)
    first = paced.receive_probe(Probe(10, 1, 0), True, 0)
    second = paced.receive_probe(Probe(10, 2, 0), True, 0)
    check(second.response_delay - first.response_delay >= paced.response_interval, "paced responses violate actual interval")
    return {"recovery": recovered.response_status, "cache_capacity": 2, "ttl_retry": True, "scope_forward": None, "paced_interval": second.response_delay - first.response_delay}


def sleep_mailbox_duplicate_range() -> dict[str, object]:
    mailbox = Mailbox()
    context = MailboxContext("binding", "session", active_executor(), frozenset({"write"}), 0, 10)
    command = MailboxCommand("once", 5, "binding", "session", grant(), "write", 5)
    check(mailbox.deliver(command, 1, context, True) == "E_OK", "initial command failed")
    check(mailbox.deliver(command, 2, context, True) == "E_OK", "completed result not returned")
    check(mailbox.executed == ["once"], "duplicate command executed twice")
    check(mailbox.deliver(replace(command, value=6), 2, context, True) == "E_COMMAND_CONFLICT", "command ID reuse accepted")
    outside = MailboxCommand("range", 5, "binding", "session", grant(), "write", 11)
    denied = MailboxCommand("cap", 5, "binding", "session", grant(), "write", 5, "admin")
    check(mailbox.deliver(outside, 1, context, True) == "E_RANGE", "out-of-range command executed")
    check(mailbox.deliver(denied, 1, context, True) == "E_CAPABILITY", "capability escape executed")
    return {"executions": len(mailbox.executed), "duplicate": "E_OK", "range": "E_RANGE", "capability": "E_CAPABILITY"}


def contract_bootstrap_transcript_tamper() -> dict[str, object]:
    points = [BindingPoint(1, "point")]
    schemas = {1: Schema(1, (SchemaField("value", "f64", True),))}
    caps = frozenset({"read"})
    proof = bootstrap_proof(KEY, b"d", b"n", "b", points, caps, schemas, 5)
    variants = [
        ("other", points, caps, schemas),
        ("b", [BindingPoint(1, "other")], caps, schemas),
        ("b", points, frozenset({"read", "write"}), schemas),
        ("b", points, caps, {1: Schema(1, (SchemaField("value", "i16", True),))}),
    ]
    statuses = []
    for binding_id, actual_points, actual_caps, actual_schemas in variants:
        statuses.append(BindingManager(KEY).prepare(binding_id, actual_points, actual_caps, actual_schemas,
                                                    frozenset({"value"}), True, True, b"d", b"n", proof, 5))
    check(statuses == ["E_BOOTSTRAP"] * 4, "bootstrap input mismatch accepted")
    return {"tampered": ["binding_id", "point", "capability", "schema"], "statuses": statuses}


def distributed_partition_shared_executor() -> dict[str, object]:
    executor = active_executor(grant())
    provider = Provider(executor, [CapabilityPoint("point", 1, 0, 100)])
    old_controller = Controller("old", binding_manager("old", frozenset({"read", "write"})), provider)
    new_controller = Controller("new", binding_manager("new", frozenset({"read", "write"})), provider, online=False)
    old_controller.bindings.commit("old")
    new_controller.bindings.commit("new")
    old = grant()
    new = grant("b", "tb", 2)
    check(executor.offer_grant(new, 1) == "E_WAIT_RELEASE", "partition grant not pending")
    before = old_controller.write("old", "point", 10, old, 9.9)
    check(before == "E_OK", "old owner failed before TTL")
    check(executor.write(new, 9.9, "new") == "E_FENCING", "new owner wrote in partition")
    check(executor.activate_pending(10) == "E_PENDING_ACK", "boundary handover failed")
    old_at_boundary = old_controller.write("old", "point", 11, old, 10)
    isolated = new_controller.write("new", "point", 12, new, 10)
    check(old_at_boundary == "E_FENCING" and isolated == "E_OFFLINE", "partition boundary fencing failed")
    new_controller.online = True
    check(new_controller.write("new", "point", 12, new, 10) == "E_NOT_ACTIVE", "recovery skipped ack")
    check(executor.confirm_activation(new.token, 10) == "E_OK", "recovery ack failed")
    recovered = new_controller.write("new", "point", 12, new, 10)
    check(recovered == "E_OK", "recovery write failed")
    return {"before_ttl": before, "old_at_ttl": old_at_boundary, "partition_new": isolated, "recovered": recovered}


def distributed_wire_dedup_bounded() -> dict[str, object]:
    dedup = FrameDeduplicator(capacity=2, ttl=5)
    wire = encode_frame(frame(b"same", AUTH_FLAG), KEY)
    first = dedup.accept(wire, 0)
    second_path = dedup.accept(wire, 0)
    check(first and not second_path and dedup.processed == 1, "two-path frame processed twice")
    dedup.accept(encode_frame(frame(b"two")), 0)
    dedup.accept(encode_frame(frame(b"three")), 0)
    check(dedup.cache_size == 2, "wire dedup cache unbounded")
    check(dedup.accept(wire, 5), "TTL retry suppressed")
    return {"processed_before_expiry": 1, "capacity": 2, "ttl_retry": True}


def security_expired_and_released_revival() -> dict[str, object]:
    expired_grant = grant()
    expired_executor = active_executor(expired_grant)
    check(expired_executor.write(expired_grant, 10, "old") == "E_EXPIRED", "expiry missing")
    expired_status = expired_executor.offer_grant(expired_grant, 10)
    check(expired_status == "E_EXPIRED" and expired_executor.active_deadline == 10, "expired grant revived")
    released_grant = grant()
    released_executor = active_executor(released_grant)
    released_executor.confirm_release(released_grant.owner, released_grant.token, 1)
    released_status = released_executor.offer_grant(released_grant, 2)
    check(released_status == "E_RELEASED" and released_executor.active_deadline == 10, "released grant revived")
    check(expired_executor.offer_grant(grant("b", "tb", 2), 10) == "E_PENDING_ACK", "higher grant after expiry rejected")
    check(released_executor.offer_grant(grant("b", "tb", 2), 2) == "E_PENDING_ACK", "higher grant after release rejected")
    return {"expired_revival": expired_status, "released_revival": released_status, "higher_epoch": "E_PENDING_ACK"}


def security_grant_fingerprint_idempotency() -> dict[str, object]:
    current = grant()
    executor = active_executor(current)
    check(executor.offer_grant(current, 2) == "E_OK" and executor.active_deadline == 10, "active duplicate extended lease")
    conflicts = [replace(current, owner="b"), replace(current, token="tb"), replace(current, ttl=20)]
    statuses = [executor.offer_grant(item, 2) for item in conflicts]
    check(statuses == ["E_GRANT_CONFLICT"] * 3, "same-epoch fingerprint mutation accepted")
    pending = grant("b", "tb", 2)
    check(executor.offer_grant(pending, 2) == "E_WAIT_RELEASE", "pending offer failed")
    check(executor.offer_grant(pending, 8) == "E_WAIT_RELEASE" and executor.active_deadline == 10, "pending duplicate changed state")
    return {"duplicate_deadline": 10, "fingerprint_conflicts": statuses, "pending_duplicate": "E_WAIT_RELEASE"}


def security_restart_authority_proof() -> dict[str, object]:
    storage: dict[str, object] = {}
    executor = active_executor(grant(), storage)
    executor.restart()
    restarted = Executor("member", storage)
    same_epoch = grant("b", "tb", 2, "auth-b", 1)
    high_epoch = grant("b", "tb", 2, "auth-b", 2)
    check(storage["authority_id"] == "auth-a", "last trusted authority ID not persisted")
    same_status = restarted.offer_grant(same_epoch, 1)
    high_status = restarted.offer_grant(high_epoch, 1)
    check(same_status == "E_UNTRUSTED_AUTHORITY", "restart allowed same-epoch authority switch")
    check(high_status == "E_UNTRUSTED_AUTHORITY", "restart allowed unwitnessed higher authority")
    proof = AuthorityProof("auth-b", 2, True, True)
    proved = restarted.offer_grant(high_epoch, 1, proof)
    check(proved == "E_PENDING_ACK", "valid post-restart authority proof rejected")
    check(storage["authority_id"] == "auth-b", "proved authority ID not persisted")
    return {"same_epoch_no_proof": same_status, "higher_epoch_no_proof": high_status, "higher_epoch_proof": proved, "persisted_authority": storage["authority_id"]}


SCENARIOS: list[tuple[str, str, Scenario]] = [
    ("discovery_announce_schedule", "discovery", discovery_announce_schedule),
    ("discovery_probe_dedup_forward", "discovery", discovery_probe_dedup_forward),
    ("frame_std_rt_roundtrip", "frame", frame_std_rt_roundtrip),
    ("frame_stream_resilience", "frame", frame_stream_resilience),
    ("frame_auth_crc_errors", "frame", frame_auth_crc_errors),
    ("sleep_deadlines", "sleep", sleep_deadlines),
    ("sleep_mailbox_reauth", "sleep", sleep_mailbox_reauth),
    ("contract_match_constraints", "contract", contract_match_constraints),
    ("contract_negotiate_bind_lifecycle", "contract", contract_negotiate_bind_lifecycle),
    ("schema_namespace_change", "schema", schema_namespace_change),
    ("distributed_controller_isolation", "distributed", distributed_controller_isolation),
    ("distributed_relay_loop_tamper", "distributed", distributed_relay_loop_tamper),
    ("security_handover_release", "security", security_handover_release),
    ("security_handover_ttl", "security", security_handover_ttl),
    ("security_authority_proof", "security", security_authority_proof),
    ("security_restart_fence", "security", security_restart_fence),
    ("frame_golden_vectors_and_tamper", "frame", frame_golden_vectors_and_tamper),
    ("frame_version_type_profile_negative", "frame", frame_version_type_profile_negative),
    ("discovery_recovery_cache_scope_rate", "discovery", discovery_recovery_cache_scope_rate),
    ("sleep_mailbox_duplicate_range", "sleep", sleep_mailbox_duplicate_range),
    ("contract_bootstrap_transcript_tamper", "contract", contract_bootstrap_transcript_tamper),
    ("distributed_partition_shared_executor", "distributed", distributed_partition_shared_executor),
    ("distributed_wire_dedup_bounded", "distributed", distributed_wire_dedup_bounded),
    ("security_expired_and_released_revival", "security", security_expired_and_released_revival),
    ("security_grant_fingerprint_idempotency", "security", security_grant_fingerprint_idempotency),
    ("security_restart_authority_proof", "security", security_restart_authority_proof),
]


def main() -> int:
    records: list[dict[str, object]] = []
    for name, category, scenario in SCENARIOS:
        try:
            details = scenario()
            status = "passed"
        except Exception as exc:
            details = {"error": f"{type(exc).__name__}: {exc}"}
            status = "failed"
        records.append({"name": name, "category": category, "status": status, "details": details})
        print(f"[{status.upper():6}] {category:11} {name} :: {details}")
    passed = sum(item["status"] == "passed" for item in records)
    failed = len(records) - passed
    report = {
        "version": PROTOCOL_VERSION,
        "seed": SEED,
        "total": len(records),
        "passed": passed,
        "failed": failed,
        "scenarios": records,
    }
    output = Path(__file__).resolve().with_name("simulation-results.json")
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n{PROTOCOL_VERSION} seed={SEED} total={len(records)} passed={passed} failed={failed}")
    print(f"Results: {output}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
