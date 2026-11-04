from __future__ import annotations

import random
import unittest
from dataclasses import replace

import idcell_sim as sim

from idcell_sim import (
    AUTH_FLAG, HEADER_LEN, PROF_RT, PROF_STD, SYNC, TYPE_DISCOVER, TYPE_READ,
    TYPE_RT_DATA, TYPE_WRITE, VERSION, AnnounceScheduler, AuthorityProof,
    BindingManager, BindingPoint, CapabilityPoint, Controller, DiscoveryAgent,
    EventQueue, Executor, Frame, FrameDeduplicator, Grant, Mailbox,
    MailboxCommand, MailboxContext, Presence, Probe, Provider, RoutedFrame,
    Schema, SchemaField, StreamParser, UnitDescriptor, WantDescriptor,
    bootstrap_proof, check_schema_change, crc16_ccitt_false, decode_tlvs,
    encode_frame, encode_tlvs, make_schema_id, match_units, negotiate,
    relay_frame,
)

KEY = b"deterministic-test-key"
GOLDEN_KEY = b"golden-key"
GOLDEN_NOAUTH = bytes.fromhex(
    "a5a50b00000801020304000301020304050607081112131415161718"
    "191a1b1c1d1e1f204142430ae95aa5"
)
GOLDEN_AUTH = bytes.fromhex(
    "a5a50b00200921222324000331323334353637384142434445464748"
    "495051525354555658595a536fa86bb6e59c593874eb0d0e34a95517fa5aa5"
)


def independent_crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def recrc(wire: bytes) -> bytes:
    mutable = bytearray(wire)
    payload_len = int.from_bytes(mutable[10:12], "big")
    tag_len = 16 if mutable[4] & AUTH_FLAG else 0
    crc_at = HEADER_LEN + payload_len + tag_len
    mutable[crc_at:crc_at + 2] = independent_crc16(bytes(mutable[:crc_at])).to_bytes(2, "big")
    return bytes(mutable)


def flipped(wire: bytes, offset: int) -> bytes:
    mutable = bytearray(wire)
    mutable[offset] ^= 1
    return recrc(bytes(mutable))


def sample_frame(payload: bytes = b"abc", flags: int = 0,
                 prof: int = PROF_STD, frame_type: int = TYPE_DISCOVER,
                 ver: int = VERSION) -> Frame:
    return Frame(payload=payload, flags=flags, prof=prof, frame_type=frame_type,
                 ver=ver, seq=7, txn=9, src=11, dst=22, group=3, ts=0x010203040506)


def golden_frame(authenticated: bool = False) -> Frame:
    if not authenticated:
        return Frame(payload=b"ABC", frame_type=TYPE_READ, seq=0x0102, txn=0x0304,
                     src=0x0102030405060708, dst=0x1112131415161718,
                     group=0x191A, ts=0x1B1C1D1E1F20)
    return Frame(payload=b"XYZ", flags=AUTH_FLAG, frame_type=TYPE_WRITE,
                 seq=0x2122, txn=0x2324, src=0x3132333435363738,
                 dst=0x4142434445464748, group=0x4950, ts=0x515253545556)


def sample_grant(owner: str = "owner-a", token: str = "token-a", grant_epoch: int = 1,
                 authority_id: str = "authority-a", authority_epoch: int = 1,
                 member_epoch: int = 1, ttl: float = 10.0) -> Grant:
    return Grant(authority_id, authority_epoch, member_epoch, owner,
                 grant_epoch, token, ttl)


def active_executor(selected: Grant | None = None,
                    storage: dict[str, object] | None = None) -> Executor:
    executor = Executor("member", storage)
    current = selected or sample_grant()
    assert executor.offer_grant(current, 0.0) == "E_PENDING_ACK"
    assert executor.confirm_activation(current.token, 0.0) == "E_OK"
    return executor


def schema(schema_id: int = 1, value_type: str = "f64") -> Schema:
    return Schema(schema_id, (SchemaField("value", value_type, True),))


def binding_proof(binding_id: str = "bind", points: list[BindingPoint] | None = None,
                  cap_list: frozenset[str] = frozenset({"read", "write"}),
                  schemas: dict[int, Schema] | None = None,
                  description: bytes = b"descriptor-v1",
                  negotiation: bytes = b"period-v1", period: float = 5.0) -> bytes:
    actual_points = points if points is not None else [BindingPoint(1, "temperature")]
    actual_schemas = schemas if schemas is not None else {1: schema()}
    return bootstrap_proof(KEY, description, negotiation, binding_id, actual_points,
                           cap_list, actual_schemas, period)


def prepared_manager(binding_id: str = "bind",
                     cap_list: frozenset[str] = frozenset({"read", "write"}),
                     period: float = 5.0) -> BindingManager:
    manager = BindingManager(KEY)
    description = b"descriptor-v1"
    negotiation = b"period-v1"
    points = [BindingPoint(1, "temperature")]
    schemas = {1: schema()}
    status = manager.prepare(
        binding_id, points, cap_list, schemas, frozenset({"value"}), True, True,
        description, negotiation,
        bootstrap_proof(KEY, description, negotiation, binding_id, points, cap_list, schemas, period),
        period,
    )
    assert status == "E_OK"
    return manager


class FrameTests(unittest.TestCase):
    def test_01_fixed_header_layout_and_std_roundtrip(self) -> None:
        frame = sample_frame(encode_tlvs([(1, b"room"), (2, b"21.5")]))
        wire = encode_frame(frame)
        self.assertEqual(36, HEADER_LEN)
        self.assertEqual(HEADER_LEN, len(frame.header()))
        self.assertEqual(SYNC, wire[:2])
        self.assertEqual(len(frame.payload), int.from_bytes(wire[10:12], "big"))
        self.assertEqual(frame.src.to_bytes(8, "big"), wire[12:20])
        self.assertEqual(frame.dst.to_bytes(8, "big"), wire[20:28])
        self.assertEqual(frame.group.to_bytes(2, "big"), wire[28:30])
        self.assertEqual(frame.ts.to_bytes(6, "big"), wire[30:36])
        self.assertEqual(HEADER_LEN + len(frame.payload) + 4, len(wire))
        result = StreamParser().feed(wire)
        self.assertEqual("OK_STD", result[0].status)
        self.assertEqual(frame, result[0].frame)
        self.assertEqual(b"room", decode_tlvs(result[0].frame.payload)[0][1])

    def test_02_profile_selects_rt_fixed_payload(self) -> None:
        wire = encode_frame(sample_frame(b"\x00\xFF\x10", prof=PROF_RT, frame_type=TYPE_READ))
        result = StreamParser(rt_payload_size=3).feed(wire)
        self.assertEqual("OK_RT", result[0].status)
        self.assertEqual(TYPE_READ, result[0].frame.frame_type)
        self.assertEqual("BAD_LENGTH", StreamParser(rt_payload_size=4).feed(wire)[0].status)

    def test_03_every_split_and_coalescing(self) -> None:
        first = encode_frame(sample_frame(b"first"))
        second = encode_frame(sample_frame(b"second"))
        wire = first + second
        for split in range(len(wire) + 1):
            parser = StreamParser()
            results = parser.feed(wire[:split]) + parser.feed(wire[split:])
            frames = [item.frame for item in results if item.frame is not None]
            self.assertEqual([b"first", b"second"], [item.payload for item in frames])
            self.assertEqual(0, parser.buffered_bytes)

    def test_04_oversize_len_never_materializes_payload(self) -> None:
        parser = StreamParser(max_payload=8)
        results = parser.feed(encode_frame(sample_frame(b"x" * 128)))
        self.assertEqual("BAD_LENGTH", results[0].status)
        self.assertEqual(0, parser.payload_materializations)
        valid = StreamParser(max_payload=8)
        valid.feed(encode_frame(sample_frame(b"ok")))
        self.assertEqual(1, valid.payload_materializations)

    def test_05_bad_crc(self) -> None:
        wire = bytearray(encode_frame(sample_frame()))
        wire[HEADER_LEN] ^= 1
        self.assertEqual("BAD_CRC", StreamParser().feed(bytes(wire))[0].status)

    def test_06_bad_hmac_with_valid_crc(self) -> None:
        wire = encode_frame(sample_frame(flags=AUTH_FLAG), b"wrong-key")
        self.assertEqual("BAD_AUTH", StreamParser(KEY).feed(wire)[0].status)

    def test_07_bad_trailer(self) -> None:
        wire = bytearray(encode_frame(sample_frame()))
        wire[-1] ^= 1
        self.assertEqual("BAD_TRAILER", StreamParser().feed(bytes(wire))[0].status)

    def test_08_half_sync_survives_feed_boundary(self) -> None:
        wire = encode_frame(sample_frame())
        parser = StreamParser()
        parser.feed(b"\xA5")
        self.assertEqual(1, parser.buffered_bytes)
        self.assertEqual("OK_STD", parser.feed(wire[1:])[-1].status)

    def test_09_crc_known_vector(self) -> None:
        self.assertEqual(0x29B1, crc16_ccitt_false(b"123456789"))
        self.assertEqual(0x29B1, independent_crc16(b"123456789"))

    def test_10_golden_wire_without_auth(self) -> None:
        actual = encode_frame(golden_frame())
        self.assertEqual(GOLDEN_NOAUTH, actual)
        self.assertEqual(bytes.fromhex("a5a50b00000801020304000301020304050607081112131415161718191a1b1c1d1e1f20"), actual[:36])
        self.assertEqual(8, actual[5])
        self.assertEqual(b"ABC", actual[36:39])
        self.assertEqual(bytes.fromhex("0ae9"), actual[39:41])
        self.assertEqual(bytes.fromhex("5aa5"), actual[41:])
        self.assertEqual("OK_STD", StreamParser().feed(GOLDEN_NOAUTH)[0].status)

    def test_11_golden_wire_with_auth(self) -> None:
        actual = encode_frame(golden_frame(True), GOLDEN_KEY)
        self.assertEqual(GOLDEN_AUTH, actual)
        self.assertEqual(bytes.fromhex("a5a50b002009212223240003313233343536373841424344454647484950515253545556"), actual[:36])
        self.assertEqual(9, actual[5])
        self.assertEqual(b"XYZ", actual[36:39])
        self.assertEqual(bytes.fromhex("536fa86bb6e59c593874eb0d0e34a955"), actual[39:55])
        self.assertEqual(bytes.fromhex("17fa"), actual[55:57])
        self.assertEqual(bytes.fromhex("5aa5"), actual[57:])
        self.assertEqual("OK_STD", StreamParser(GOLDEN_KEY).feed(GOLDEN_AUTH)[0].status)

    def test_12_seq_tamper_detected_after_independent_recrc(self) -> None:
        self.assertEqual("BAD_AUTH", StreamParser(GOLDEN_KEY).feed(flipped(GOLDEN_AUTH, 6))[0].status)

    def test_13_src_tamper_detected_after_independent_recrc(self) -> None:
        self.assertEqual("BAD_AUTH", StreamParser(GOLDEN_KEY).feed(flipped(GOLDEN_AUTH, 12))[0].status)

    def test_14_dst_tamper_detected_after_independent_recrc(self) -> None:
        self.assertEqual("BAD_AUTH", StreamParser(GOLDEN_KEY).feed(flipped(GOLDEN_AUTH, 20))[0].status)

    def test_15_ts_tamper_detected_after_independent_recrc(self) -> None:
        self.assertEqual("BAD_AUTH", StreamParser(GOLDEN_KEY).feed(flipped(GOLDEN_AUTH, 30))[0].status)

    def test_16_auth_tag_tamper_detected_after_independent_recrc(self) -> None:
        self.assertEqual("BAD_AUTH", StreamParser(GOLDEN_KEY).feed(flipped(GOLDEN_AUTH, 39))[0].status)

    def test_17_version_profile_and_unknown_type_rejected(self) -> None:
        for offset, value, expected in ((2, 0x1B, "BAD_VERSION"),
                                        (3, 2, "BAD_PROFILE"), (5, 0xFF, "BAD_TYPE")):
            with self.subTest(offset=offset, value=value):
                mutable = bytearray(encode_frame(sample_frame()))
                mutable[offset] = value
                self.assertEqual(expected, StreamParser().feed(recrc(bytes(mutable)))[0].status)
        with self.assertRaises(ValueError):
            encode_frame(sample_frame(frame_type=0xFF))
        compatible_minor = sample_frame(ver=VERSION + 1)
        result = StreamParser().feed(encode_frame(compatible_minor))[0]
        self.assertEqual("OK_STD", result.status)
        self.assertEqual(VERSION + 1, result.frame.ver)

    def test_18_type_is_semantic_not_profile_selector(self) -> None:
        self.assertEqual(
            tuple(range(1, 26)),
            (sim.TYPE_DISCOVER, sim.TYPE_HELLO, sim.TYPE_MATCH, sim.TYPE_NEGOTIATE,
             sim.TYPE_RENEGOTIATE, sim.TYPE_AUTH, sim.TYPE_BIND, sim.TYPE_READ,
             sim.TYPE_WRITE, sim.TYPE_SUBSCRIBE, sim.TYPE_UNSUB, sim.TYPE_EVENT,
             sim.TYPE_CMD, sim.TYPE_ACK, sim.TYPE_DONE, sim.TYPE_LEASE,
             sim.TYPE_PREEMPT, sim.TYPE_GROUP, sim.TYPE_HEARTBEAT, sim.TYPE_OFFLINE,
             sim.TYPE_STALE, sim.TYPE_CONFIG, sim.TYPE_PROVISION, sim.TYPE_ERROR,
             sim.TYPE_RT_DATA),
        )
        self.assertEqual(frozenset(range(1, 26)), sim.VALID_TYPES)
        self.assertEqual((8, 9, 6, 7), (sim.TYPE_READ, sim.TYPE_WRITE, sim.TYPE_AUTH, sim.TYPE_BIND))
        rt = sample_frame(b"rt", prof=PROF_RT, frame_type=TYPE_READ)
        std = sample_frame(b"std", prof=PROF_STD, frame_type=TYPE_RT_DATA)
        results = StreamParser(rt_payload_size=2).feed(encode_frame(rt) + encode_frame(std))
        self.assertEqual(["OK_RT", "OK_STD"], [item.status for item in results])
        self.assertEqual(VERSION, results[0].frame.ver)

    def test_18b_in_range_bad_len_does_not_drop_next_frame(self) -> None:
        first = bytearray(encode_frame(sample_frame(b"abc")))
        second = encode_frame(sample_frame(b"12345"))
        self.assertEqual((43, 45), (len(first), len(second)))
        first[10:12] = (48).to_bytes(2, "big")
        parser = StreamParser()
        results = parser.feed(bytes(first) + second)
        self.assertEqual("BAD_CRC", results[0].status)
        delivered = [item.frame for item in results if item.frame is not None]
        self.assertEqual([b"12345"], [item.payload for item in delivered])
        self.assertEqual(0, parser.buffered_bytes)


class DiscoveryTests(unittest.TestCase):
    def test_19_seeded_jitter_backoff_cap_and_fixed_confirmed_period(self) -> None:
        events = EventQueue()
        announce = AnnounceScheduler(events, 1, seed=19, base=2, retry_max=5, period=20, initial_jitter=3)
        announce.start()
        self.assertEqual(random.Random(19).uniform(0, 3), announce.next_delay)
        events.run_until(100)
        self.assertGreater(announce.failures, 3)
        self.assertLessEqual(announce.next_delay, 5)
        announce.confirm()
        events.run_until(events.now + 80)
        intervals = [b - a for a, b in zip(announce.announcements, announce.announcements[1:])]
        self.assertEqual([20.0, 20.0, 20.0], intervals[-3:])

    def test_20_probe_dedup_is_scoped_by_originator(self) -> None:
        agent = DiscoveryAgent()
        self.assertTrue(agent.receive_probe(Probe(1, 8, 2)).accepted)
        self.assertFalse(agent.receive_probe(Probe(1, 8, 2)).accepted)
        self.assertTrue(agent.receive_probe(Probe(2, 8, 2)).accepted)
        self.assertEqual(2, agent.descriptor_fetches)

    def test_21_hop_limit_and_scope_restrict_forwarding(self) -> None:
        agent = DiscoveryAgent(scope="building-a")
        outside = agent.receive_probe(Probe(1, 1, 3, scope="building-b"))
        self.assertIsNone(outside.forwarded)
        self.assertFalse(outside.accepted)
        self.assertFalse(outside.descriptor_loaded)
        self.assertEqual("E_SCOPE", outside.response_status)
        self.assertEqual(0, agent.descriptor_fetches)
        inside = agent.receive_probe(Probe(2, 1, 1, scope="building-a"))
        self.assertEqual(0, inside.forwarded.hop_limit)
        terminal = DiscoveryAgent(scope="building-a").receive_probe(Probe(3, 1, 0, scope="building-a"))
        self.assertIsNone(terminal.forwarded)

    def test_22_descriptor_failure_does_not_suppress_recovery(self) -> None:
        agent = DiscoveryAgent()
        failed = agent.receive_probe(Probe(1, 4, 1), descriptor_available=False)
        self.assertEqual("E_UNAVAILABLE", failed.response_status)
        self.assertEqual(1, agent.cache_size)
        self.assertIsNotNone(failed.forwarded)
        recovered = agent.receive_probe(Probe(1, 4, 1), descriptor_available=True)
        self.assertTrue(recovered.descriptor_loaded)
        self.assertEqual(1, agent.descriptor_fetches)

    def test_23_dedup_cache_capacity_and_lru_eviction(self) -> None:
        agent = DiscoveryAgent(cache_capacity=2, cache_ttl=100)
        agent.receive_probe(Probe(1, 1, 0))
        agent.receive_probe(Probe(1, 2, 0))
        agent.receive_probe(Probe(1, 1, 0))  # refresh query 1 in LRU
        agent.receive_probe(Probe(1, 3, 0))
        self.assertNotIn((1, 2), agent.seen)
        self.assertEqual(2, agent.cache_size)
        self.assertTrue(agent.receive_probe(Probe(1, 2, 0)).accepted)

    def test_24_dedup_cache_ttl_allows_later_retry(self) -> None:
        agent = DiscoveryAgent(cache_ttl=5)
        agent.receive_probe(Probe(1, 1, 0), now=0)
        self.assertFalse(agent.receive_probe(Probe(1, 1, 0), now=4.9).accepted)
        self.assertTrue(agent.receive_probe(Probe(1, 1, 0), now=5).accepted)

    def test_25_response_limit_and_random_delay_are_seeded(self) -> None:
        one = DiscoveryAgent(response_rate=2, response_max_jitter=0.25, seed=77)
        two = DiscoveryAgent(response_rate=2, response_max_jitter=0.25, seed=77)
        first = one.receive_probe(Probe(1, 1, 0), now=0)
        second = one.receive_probe(Probe(1, 2, 0), now=0)
        peer_first = two.receive_probe(Probe(1, 1, 0), now=0)
        peer_second = two.receive_probe(Probe(1, 2, 0), now=0)
        self.assertEqual(first.response_delay, peer_first.response_delay)
        self.assertEqual(second.response_delay, peer_second.response_delay)
        self.assertGreaterEqual(second.response_delay, 0.5)
        self.assertGreaterEqual(second.response_delay - first.response_delay, one.response_interval)

    def test_26_dual_path_duplicate_probe_is_processed_once(self) -> None:
        agent = DiscoveryAgent()
        path_a = Probe(9, 3, 2, scope="default")
        path_b = Probe(9, 3, 1, scope="default")
        self.assertTrue(agent.receive_probe(path_a).accepted)
        self.assertFalse(agent.receive_probe(path_b).accepted)
        self.assertEqual(1, agent.descriptor_fetches)


class RelayAndFilteringTests(unittest.TestCase):
    def test_71_relay_preserves_endpoints_and_retries_send(self) -> None:
        agent = DiscoveryAgent(node_id=99)
        probe = Probe(1, 70, 2, "temperature", target_id=20, src_id=10, dst_id=20)
        failed = agent.receive_probe(probe, descriptor_available=False, forward_ok=False)
        self.assertEqual("E_SEND", failed.response_status)
        self.assertEqual(0, agent.cache_size)
        relayed = agent.receive_probe(probe, descriptor_available=False)
        self.assertEqual((10, 20, 1),
                         (relayed.forwarded.src_id, relayed.forwarded.dst_id, relayed.forwarded.hop_limit))
        self.assertEqual(0, agent.descriptor_fetches)
        self.assertIsNone(relayed.response_delay)

    def test_72_target_and_query_filter_local_response(self) -> None:
        agent = DiscoveryAgent(node_id=1, capability_labels=("temperature",), model="p1-node")
        elsewhere = agent.receive_probe(Probe(1, 71, 1, "temperature", target_id=2))
        self.assertIsNotNone(elsewhere.forwarded)
        self.assertFalse(elsewhere.descriptor_loaded)
        self.assertEqual(0, agent.descriptor_fetches)
        missing = agent.receive_probe(Probe(1, 72, 0, "nonexistent"))
        self.assertEqual("E_OK", missing.response_status)
        self.assertFalse(missing.descriptor_loaded)
        self.assertEqual(0, agent.descriptor_fetches)

    def test_73_response_send_failure_and_abandon_recovery(self) -> None:
        agent = DiscoveryAgent(node_id=1, capability_labels=("temperature",))
        probe = Probe(1, 73, 0, "temperature")
        failed = agent.receive_probe(probe, response_send_ok=False)
        self.assertEqual("E_SEND", failed.response_status)
        recovered = agent.receive_probe(probe)
        self.assertEqual("E_OK", recovered.response_status)
        self.assertTrue(recovered.descriptor_loaded)
        agent.abandon_response(1, 73)
        self.assertEqual(0, agent.cache_size)
        self.assertEqual("E_OK", agent.receive_probe(probe).response_status)


class SleepAndMailboxTests(unittest.TestCase):
    def test_27_unscheduled_three_heartbeat_offline(self) -> None:
        presence = Presence(heartbeat=5)
        self.assertEqual("ONLINE", presence.state(14.9))
        self.assertEqual("OFFLINE", presence.state(15))
        presence.receive_valid(20)
        self.assertEqual("ONLINE", presence.state(34.9))

    def test_28_scheduled_sleep_upper_bound_and_automatic_checkin(self) -> None:
        presence = Presence(5, scheduled_period=20, max_wake_latency=30)
        presence.sleep()
        self.assertEqual("ASLEEP", presence.state(29.9))
        self.assertEqual("OFFLINE", presence.state(30))
        self.assertEqual("CHECK_IN", presence.wake(31))
        self.assertEqual("ONLINE", presence.state(31))

    def test_29_scheduled_valid_frame_wakes_and_updates_reachability(self) -> None:
        presence = Presence(5, scheduled_period=20, max_wake_latency=30)
        presence.sleep()
        self.assertEqual("ASLEEP", presence.state(10))
        presence.receive_valid(10)
        self.assertEqual("ONLINE", presence.state(10))
        self.assertEqual("ONLINE", presence.state(39.9))
        self.assertEqual("OFFLINE", presence.state(40))

    def test_30_mailbox_positive_and_expiry(self) -> None:
        mailbox = Mailbox()
        context = MailboxContext("bind", "session", active_executor())
        command = MailboxCommand("c1", 5, "bind", "session", sample_grant(), "write")
        self.assertEqual("E_OK", mailbox.deliver(command, 1, context, True))
        self.assertEqual("E_EXPIRED", mailbox.deliver(MailboxCommand("c2", 5, "bind", "session", sample_grant(), "w"), 6, context, True))
        self.assertEqual(["c1"], mailbox.executed)

    def test_31_mailbox_reauth_context_session_and_old_epoch(self) -> None:
        mailbox = Mailbox()
        context = MailboxContext("bind", "session", active_executor())
        command = MailboxCommand("c1", 50, "bind", "session", sample_grant(), "write")
        self.assertEqual("E_AUTH", mailbox.deliver(command, 1, context, False))
        self.assertEqual("E_BINDING", mailbox.deliver(MailboxCommand("c2", 50, "old", "session", sample_grant(), "w"), 1, context, True))
        self.assertEqual("E_SESSION", mailbox.deliver(MailboxCommand("c3", 50, "bind", "old", sample_grant(), "w"), 1, context, True))
        self.assertEqual("E_FENCING", mailbox.deliver(MailboxCommand("c4", 50, "bind", "session", sample_grant(authority_epoch=0, grant_epoch=0), "w"), 1, context, True))
        self.assertEqual([], mailbox.executed)

    def test_32_mailbox_completed_result_prevents_duplicate_execution(self) -> None:
        mailbox = Mailbox()
        context = MailboxContext("bind", "session", active_executor())
        command = MailboxCommand("same", 5, "bind", "session", sample_grant(), "write", 4)
        self.assertEqual("E_OK", mailbox.deliver(command, 1, context, True))
        self.assertEqual("E_OK", mailbox.deliver(command, 2, context, True))
        self.assertEqual("E_OK", mailbox.deliver(command, 6, context, True))
        self.assertEqual("E_COMMAND_CONFLICT", mailbox.deliver(replace(command, value=5), 2, context, True))
        self.assertEqual(["same"], mailbox.executed)

    def test_33_mailbox_capability_and_range_are_checked_before_execution(self) -> None:
        mailbox = Mailbox()
        context = MailboxContext("bind", "session", active_executor(),
                                 frozenset({"write"}), 0, 10)
        outside = MailboxCommand("range", 5, "bind", "session", sample_grant(), "w", 11)
        denied = MailboxCommand("cap", 5, "bind", "session", sample_grant(), "w", 5, "admin")
        self.assertEqual("E_RANGE", mailbox.deliver(outside, 1, context, True))
        self.assertEqual("E_CAPABILITY", mailbox.deliver(denied, 1, context, True))
        self.assertEqual([], mailbox.executed)


class SuspendedAndOfflineTests(unittest.TestCase):
    def test_74_suspended_wake_requires_new_context(self) -> None:
        mailbox = Mailbox()
        old_grant = sample_grant()
        context = MailboxContext("bind", "session", active_executor(old_grant))
        old = MailboxCommand("old", 50, "bind", "session", old_grant, "write", 4)
        context.suspend()
        self.assertEqual("E_SUSPENDED", mailbox.deliver(old, 1, context, True))
        context.wake()
        self.assertEqual("E_SUSPENDED", mailbox.deliver(old, 2, context, True))
        new_grant = sample_grant("owner-b", "token-b", 2, authority_epoch=2, member_epoch=2)
        context.activate("new-bind", "new-session", active_executor(new_grant))
        self.assertEqual("E_BINDING", mailbox.deliver(old, 3, context, True))
        new = MailboxCommand("new", 50, "new-bind", "new-session", new_grant, "write", 5)
        self.assertEqual("E_OK", mailbox.deliver(new, 3, context, True))
        self.assertEqual(["new"], mailbox.executed)

    def test_75_offline_is_sticky_and_nan_inf_rejected(self) -> None:
        presence = Presence(5)
        presence.receive_valid(0)
        presence.offline()
        presence.receive_ordinary(1)
        self.assertEqual("OFFLINE", presence.state(1))
        presence.receive_valid(2)
        self.assertEqual("ONLINE", presence.state(2))
        mailbox = Mailbox()
        context = MailboxContext("bind", "session", active_executor())
        for value in (float("nan"), float("inf"), float("-inf")):
            command = MailboxCommand(str(value), 50, "bind", "session", sample_grant(), "write", value)
            self.assertEqual("E_RANGE", mailbox.deliver(command, 1, context, True))
        self.assertEqual([], mailbox.executed)


class ContractTests(unittest.TestCase):
    def test_34_match_returns_all_candidates_and_all_hard_failures(self) -> None:
        units = [
            UnitDescriptor("a", "temperature", -10, 50, "f64", frozenset({"read"})),
            UnitDescriptor("b", "temperature", -20, 60, "f64", frozenset({"read", "write"})),
            UnitDescriptor("c", "humidity", 0, 100, "f64", frozenset({"read"})),
        ]
        want = WantDescriptor("temperature", 0, 40, "f64", frozenset({"read"}))
        result = match_units(units, want)
        self.assertEqual(("a", "b"), result.candidates)
        self.assertIn("E_QUANTITY", result.candidate_reasons["c"])

    def test_35_no_candidate_has_top_and_unit_reasons(self) -> None:
        unit = UnitDescriptor("a", "temperature", 0, 10, "f64", frozenset())
        want = WantDescriptor("temperature", -5, 20, "i16", frozenset({"write"}))
        result = match_units([unit], want)
        self.assertEqual("E_NOMATCH", result.status)
        self.assertEqual("E_UNIT", result.reason)
        self.assertEqual(("E_DOMAIN", "E_TYPE", "E_PERMISSION"), result.candidate_reasons["a"])

    def test_36_incomplete_public_descriptions_cannot_match(self) -> None:
        unit = UnitDescriptor("a", "temperature", 0, 10, "f64", frozenset(), False)
        want = WantDescriptor("temperature", 0, 10, "f64", frozenset())
        self.assertEqual("E_NOMATCH", match_units([unit], want).status)
        self.assertEqual("E_INCOMPLETE", match_units([unit], replace(want, public_complete=False)).status)

    def test_37_negotiation_uses_max_and_stale_bound(self) -> None:
        accepted = negotiate(3, 8, 5, 9)
        rejected = negotiate(3, 8, 12, 9)
        self.assertEqual(("E_OK", 8), (accepted.status, accepted.publication_period))
        self.assertEqual(("E_NEGOTIATE", 12), (rejected.status, rejected.publication_period))

    def test_38_bind_requires_auth_and_verified_authorized_view(self) -> None:
        for authenticated, view, expected in ((False, True, "E_AUTH"), (True, False, "E_VIEW")):
            manager = BindingManager(KEY)
            points = [BindingPoint(1, "x")]
            schemas = {1: schema()}
            result = manager.prepare("b", points, frozenset(), schemas, frozenset({"value"}),
                                     authenticated, view, b"d", b"n",
                                     bootstrap_proof(KEY, b"d", b"n", "b", points, frozenset(), schemas, 0), 0)
            self.assertEqual(expected, result)

    def test_39_prepared_commit_abort_and_business_visibility(self) -> None:
        committed = prepared_manager()
        self.assertFalse(committed.visible("bind"))
        self.assertEqual("E_NO_ACTIVE_BIND", committed.access("bind", "read"))
        self.assertEqual("E_OK", committed.commit("bind"))
        self.assertTrue(committed.visible("bind"))
        aborted = prepared_manager()
        aborted.abort("bind")
        self.assertNotIn("bind", aborted.bindings)

    def test_40_capabilities_outside_list_are_rejected(self) -> None:
        manager = prepared_manager()
        manager.commit("bind")
        self.assertEqual("E_OK", manager.access("bind", "read"))
        self.assertEqual("E_CAPABILITY", manager.access("bind", "admin"))

    def test_41_bootstrap_description_tampering_is_detected(self) -> None:
        manager = BindingManager(KEY)
        points = [BindingPoint(1, "x")]
        schemas = {1: schema()}
        result = manager.prepare("b", points, frozenset({"read"}), schemas, frozenset({"value"}),
                                 True, True, b"tampered", b"n",
                                 bootstrap_proof(KEY, b"original", b"n", "b", points, frozenset({"read"}), schemas, 0), 0)
        self.assertEqual("E_BOOTSTRAP", result)

    def test_42_bootstrap_binding_id_and_point_tampering_are_detected(self) -> None:
        original_points = [BindingPoint(1, "x")]
        schemas = {1: schema()}
        proof = bootstrap_proof(KEY, b"d", b"n", "b", original_points, frozenset({"read"}), schemas, 0)
        for binding_id, points in (("other", original_points), ("b", [BindingPoint(1, "y")])):
            with self.subTest(binding_id=binding_id, points=points):
                result = BindingManager(KEY).prepare(binding_id, points, frozenset({"read"}), schemas,
                                                     frozenset({"value"}), True, True, b"d", b"n", proof, 0)
                self.assertEqual("E_BOOTSTRAP", result)

    def test_43_bootstrap_capability_tampering_is_detected(self) -> None:
        points = [BindingPoint(1, "x")]
        schemas = {1: schema()}
        proof = bootstrap_proof(KEY, b"d", b"n", "b", points, frozenset({"read"}), schemas, 0)
        result = BindingManager(KEY).prepare("b", points, frozenset({"read", "write"}), schemas,
                                             frozenset({"value"}), True, True, b"d", b"n", proof, 0)
        self.assertEqual("E_BOOTSTRAP", result)

    def test_44_bootstrap_schema_mapping_tampering_is_detected(self) -> None:
        points = [BindingPoint(1, "x")]
        original = {1: schema()}
        proof = bootstrap_proof(KEY, b"d", b"n", "b", points, frozenset({"read"}), original, 0)
        result = BindingManager(KEY).prepare("b", points, frozenset({"read"}), {1: schema(1, "i16")},
                                             frozenset({"value"}), True, True, b"d", b"n", proof, 0)
        self.assertEqual("E_BOOTSTRAP", result)


class SchemaTests(unittest.TestCase):
    def test_45_schema_id_is_u24_namespace_plus_u40_local(self) -> None:
        self.assertEqual(0xABCDEF0123456789, make_schema_id(0xABCDEF, 0x0123456789))
        self.assertEqual(0xFFFFFFFFFF, make_schema_id(0, 0xFFFFFFFFFF))
        self.assertEqual(0xFFFFFF0000000000, make_schema_id(0xFFFFFF, 0))
        with self.assertRaises(ValueError):
            make_schema_id(0x1000000, 0)
        with self.assertRaises(ValueError):
            make_schema_id(0, 0x10000000000)

    def test_46_structure_change_requires_new_id_and_renegotiation(self) -> None:
        old = schema(1)
        changed = Schema(2, (SchemaField("value", "i16", True),))
        self.assertEqual("E_SCHEMA_ID", check_schema_change(old, Schema(1, changed.fields), True, frozenset({"value"})))
        self.assertEqual("E_NEGOTIATE", check_schema_change(old, changed, False, frozenset({"value"})))
        self.assertEqual("E_OK", check_schema_change(old, changed, True, frozenset({"value"})))

    def test_47_unknown_critical_schema_is_rejected(self) -> None:
        unknown = Schema(2, (SchemaField("new-critical", "u8", True),))
        self.assertEqual("E_UNKNOWN_CRITICAL", check_schema_change(schema(), unknown, True, frozenset({"value"})))


class DistributedTests(unittest.TestCase):
    def _shared_controllers(self) -> tuple[Executor, Provider, Controller, Controller, Grant]:
        current = sample_grant()
        executor = active_executor(current)
        provider = Provider(executor, [CapabilityPoint("temperature", 1, 0, 100)])
        one = Controller("one", prepared_manager("one", frozenset({"read", "write"}), 5), provider)
        two = Controller("two", prepared_manager("two", frozenset({"read"}), 11), provider)
        one.bindings.commit("one")
        two.bindings.commit("two")
        return executor, provider, one, two, current

    def test_48_controllers_share_point_with_independent_periods_permissions(self) -> None:
        _, provider, one, two, current = self._shared_controllers()
        self.assertEqual(5, one.bindings.bindings["one"].publication_period)
        self.assertEqual(11, two.bindings.bindings["two"].publication_period)
        self.assertEqual("E_OK", one.write("one", "temperature", 42, current, 1))
        self.assertEqual(("E_OK", 42), two.read("two", "temperature"))
        self.assertEqual("E_CAPABILITY", two.write("two", "temperature", 43, current, 1))
        one.online = False
        self.assertEqual("E_OFFLINE", one.access("one", "read"))
        self.assertEqual(("E_OK", 42), two.read("two", "temperature"))
        self.assertIs(one.provider, provider)
        self.assertIs(two.provider, provider)

    def test_49_unbind_does_not_disturb_other_controller_and_write_is_fenced(self) -> None:
        executor, _, one, two, current = self._shared_controllers()
        two.bindings.bindings["two"].cap_list = frozenset({"read", "write"})
        one.unbind("one")
        self.assertEqual("E_NO_ACTIVE_BIND", one.access("one", "read"))
        self.assertEqual("E_OK", two.write("two", "temperature", 55, current, 2))
        self.assertEqual("E_FENCING", executor.write(sample_grant("intruder", "bad", 99), 2, "bad"))
        self.assertEqual(("E_OK", 55), two.read("two", "temperature"))

    def test_50_raw_wire_relay_needs_no_key_and_tamper_fails(self) -> None:
        wire = encode_frame(sample_frame(b"session=7;binding=4", AUTH_FLAG), KEY)
        routed = relay_frame(RoutedFrame(wire, 3))
        self.assertEqual(wire, routed.wire)
        self.assertEqual(2, routed.hop_limit)
        self.assertEqual("OK_STD", StreamParser(KEY).feed(routed.wire)[0].status)
        tampered = relay_frame(RoutedFrame(wire, 3), tamper_payload=True)
        self.assertNotEqual(wire, tampered.wire)
        self.assertEqual("BAD_AUTH", StreamParser(KEY).feed(tampered.wire)[0].status)

    def test_51_loop_frames_terminate_at_zero_hop_limit(self) -> None:
        routed = RoutedFrame(encode_frame(sample_frame()), 2)
        routed = relay_frame(routed)
        routed = relay_frame(routed)
        self.assertEqual(0, routed.hop_limit)
        self.assertIsNone(relay_frame(routed))

    def test_52_two_path_wire_duplicate_once_and_bounded_dedup(self) -> None:
        dedup = FrameDeduplicator(capacity=2, ttl=5)
        wire = encode_frame(sample_frame(b"same"))
        self.assertTrue(dedup.accept(wire, 0))
        self.assertFalse(dedup.accept(wire, 0))
        self.assertEqual(1, dedup.processed)
        dedup.accept(encode_frame(sample_frame(b"two")), 0)
        dedup.accept(encode_frame(sample_frame(b"three")), 0)
        self.assertEqual(2, dedup.cache_size)
        self.assertTrue(dedup.accept(wire, 6))

    def test_53_partition_old_ttl_boundary_and_recovery_share_executor(self) -> None:
        executor = active_executor(sample_grant())
        provider = Provider(executor, [CapabilityPoint("temperature", 1, 0, 100)])
        old_controller = Controller("old", prepared_manager("old"), provider)
        new_controller = Controller("new", prepared_manager("new"), provider, online=False)
        old_controller.bindings.commit("old")
        new_controller.bindings.commit("new")
        old = sample_grant()
        new = sample_grant("owner-b", "token-b", 2)
        self.assertEqual("E_WAIT_RELEASE", executor.offer_grant(new, 1))
        self.assertEqual("E_OK", old_controller.write("old", "temperature", 10, old, 9.9))
        self.assertEqual("E_FENCING", executor.write(new, 9.9, "partition-new"))
        self.assertEqual("E_PENDING_ACK", executor.activate_pending(10))
        self.assertEqual("E_FENCING", old_controller.write("old", "temperature", 11, old, 10))
        self.assertEqual("E_OFFLINE", new_controller.write("new", "temperature", 12, new, 10))
        new_controller.online = True
        self.assertEqual("E_NOT_ACTIVE", new_controller.write("new", "temperature", 12, new, 10))
        self.assertEqual("E_OK", executor.confirm_activation(new.token, 10))
        self.assertEqual("E_OK", new_controller.write("new", "temperature", 12, new, 10))

    def test_68_contract_point_membership_is_enforced(self) -> None:
        _, provider, one, _, current = self._shared_controllers()
        provider.points["other"] = CapabilityPoint("other", 1, 0, 100)
        self.assertEqual("E_CAPABILITY", one.write("one", "other", 42, current, 1))
        self.assertEqual(0, provider.points["other"].value)

    def test_69_point_grant_cannot_write_another_executor_domain(self) -> None:
        grant_a = sample_grant("owner-a", "token-a", 1)
        grant_b = sample_grant("owner-b", "token-b", 1, authority_id="authority-b")
        executor_a = active_executor(grant_a)
        executor_b = active_executor(grant_b)
        provider = Provider(
            executor_a,
            [CapabilityPoint("a", 1, 0, 100),
             CapabilityPoint("b", 1, 0, 100, executor_key="other")],
            {"other": executor_b},
        )
        self.assertEqual("E_OK", provider.write("a", 10, grant_a, 1, frozenset({"write"})))
        self.assertEqual("E_FENCING", provider.write("b", 20, grant_a, 1, frozenset({"write"})))
        self.assertEqual(0, provider.points["b"].value)


class FencingTests(unittest.TestCase):
    def test_54_new_owner_waits_for_release_and_activation_ack(self) -> None:
        old = sample_grant()
        executor = active_executor(old)
        new = sample_grant("owner-b", "token-b", 2)
        self.assertEqual("E_WAIT_RELEASE", executor.offer_grant(new, 1))
        self.assertEqual("E_OK", executor.write(old, 1, "old-still-valid"))
        self.assertEqual("E_PENDING_ACK", executor.confirm_release(old.owner, old.token, 2))
        self.assertEqual("E_NOT_ACTIVE", executor.write(new, 2, "too-early"))
        self.assertEqual("E_FENCING", executor.write(old, 2, "old-fenced"))
        self.assertEqual("E_OK", executor.confirm_activation(new.token, 2))
        self.assertEqual("E_OK", executor.write(new, 2, "new-active"))

    def test_55_old_local_ttl_allows_handover_without_release(self) -> None:
        executor = active_executor(sample_grant())
        new = sample_grant("owner-b", "token-b", 2)
        self.assertEqual("E_WAIT_RELEASE", executor.offer_grant(new, 9.9))
        self.assertEqual("E_PENDING_ACK", executor.activate_pending(10))
        self.assertEqual("E_NOT_ACTIVE", executor.write(new, 10, "not-yet"))

    def test_56_local_deadline_fences_active_write(self) -> None:
        current = sample_grant()
        executor = active_executor(current)
        self.assertEqual("E_OK", executor.write(current, 9.99, "valid"))
        self.assertEqual("E_EXPIRED", executor.write(current, 10, "expired"))

    def test_57_authority_switch_requires_larger_epoch_and_proof(self) -> None:
        executor = active_executor(sample_grant())
        contender = sample_grant("owner-b", "token-b", 2, "authority-b", 2)
        self.assertEqual("E_UNTRUSTED_AUTHORITY", executor.offer_grant(contender, 1))
        proof = AuthorityProof("authority-b", 2, True, True)
        self.assertEqual("E_WAIT_RELEASE", executor.offer_grant(contender, 1, proof))
        fresh = active_executor(sample_grant())
        same_epoch = sample_grant("owner-c", "token-c", 2, "authority-c", 1)
        self.assertEqual("E_UNTRUSTED_AUTHORITY", fresh.offer_grant(same_epoch, 1, AuthorityProof("authority-c", 1, True, True)))

    def test_58_restart_enforces_floor_and_requires_higher_reactivation_grant(self) -> None:
        storage: dict[str, object] = {}
        executor = active_executor(sample_grant(), storage)
        second = sample_grant("owner-b", "token-b", 2)
        executor.offer_grant(second, 1)
        executor.restart()
        restarted = Executor("member", storage)
        self.assertEqual("E_NOT_ACTIVE", restarted.write(sample_grant(), 1, "old"))
        self.assertEqual("E_STALE_EPOCH", restarted.offer_grant(second, 2))
        third = sample_grant("owner-c", "token-c", 3, "authority-a", 1)
        self.assertEqual("E_PENDING_ACK", restarted.offer_grant(third, 2))
        self.assertEqual("E_NOT_ACTIVE", restarted.write(third, 2, "before-ack"))
        self.assertEqual("E_OK", restarted.confirm_activation(third.token, 2))
        self.assertEqual("E_OK", restarted.write(third, 2, "after-ack"))

    def test_59_lower_member_and_authority_epochs_are_rejected(self) -> None:
        executor = active_executor(sample_grant(authority_epoch=3, member_epoch=4))
        self.assertEqual("E_STALE_EPOCH", executor.offer_grant(sample_grant(grant_epoch=2, authority_epoch=2, member_epoch=4), 1))
        self.assertEqual("E_STALE_EPOCH", executor.offer_grant(sample_grant(grant_epoch=2, authority_epoch=3, member_epoch=3), 1))

    def test_60_release_without_successor_immediately_fences_old_owner(self) -> None:
        current = sample_grant()
        executor = active_executor(current)
        self.assertEqual("E_OK", executor.confirm_release(current.owner, current.token, 1))
        self.assertEqual("E_FENCING", executor.write(current, 1, "released"))
        self.assertEqual([], executor.writes)

    def test_61_expired_grant_cannot_be_revived_or_extend_deadline(self) -> None:
        current = sample_grant()
        executor = active_executor(current)
        self.assertEqual("E_EXPIRED", executor.write(current, 10, "expired"))
        self.assertEqual("E_EXPIRED", executor.offer_grant(current, 10))
        self.assertEqual(10, executor.active_deadline)
        self.assertEqual("E_PENDING_ACK", executor.offer_grant(sample_grant("owner-b", "token-b", 2), 10))

    def test_62_released_grant_cannot_be_revived(self) -> None:
        current = sample_grant()
        executor = active_executor(current)
        executor.confirm_release(current.owner, current.token, 1)
        deadline = executor.active_deadline
        self.assertEqual("E_RELEASED", executor.offer_grant(current, 2))
        self.assertEqual(deadline, executor.active_deadline)
        self.assertEqual("E_PENDING_ACK", executor.offer_grant(sample_grant("owner-b", "token-b", 2), 2))

    def test_63_same_epoch_different_fingerprint_is_rejected(self) -> None:
        current = sample_grant()
        executor = active_executor(current)
        conflicts = [
            replace(current, owner="owner-b"), replace(current, token="token-b"),
            replace(current, ttl=99), replace(current, member_epoch=2),
            replace(current, authority_id="authority-b"),
        ]
        for conflict in conflicts:
            with self.subTest(conflict=conflict):
                self.assertEqual("E_GRANT_CONFLICT", executor.offer_grant(conflict, 1))
        self.assertEqual(10, executor.active_deadline)

    def test_64_pending_and_used_epoch_fingerprints_cannot_be_mutated(self) -> None:
        current = sample_grant()
        executor = active_executor(current)
        pending = sample_grant("owner-b", "token-b", 2)
        self.assertEqual("E_WAIT_RELEASE", executor.offer_grant(pending, 1))
        self.assertEqual("E_GRANT_CONFLICT", executor.offer_grant(replace(pending, token="mutated"), 2))
        self.assertEqual("E_PENDING_ACK", executor.confirm_release(current.owner, current.token, 2))
        self.assertEqual("E_GRANT_CONFLICT", executor.offer_grant(replace(current, ttl=99), 3))
        self.assertEqual("E_STALE_EPOCH", executor.offer_grant(current, 3))

    def test_65_duplicate_active_and_pending_offers_are_idempotent(self) -> None:
        current = sample_grant()
        executor = active_executor(current)
        self.assertEqual("E_OK", executor.offer_grant(current, 2))
        self.assertEqual(10, executor.active_deadline)
        pending = sample_grant("owner-b", "token-b", 2)
        self.assertEqual("E_WAIT_RELEASE", executor.offer_grant(pending, 2))
        self.assertEqual("E_WAIT_RELEASE", executor.offer_grant(pending, 8))
        self.assertEqual(10, executor.active_deadline)
        self.assertEqual("E_PENDING_ACK", executor.confirm_release(current.owner, current.token, 9))
        self.assertEqual(19, executor.active_deadline)
        self.assertEqual("E_PENDING_ACK", executor.offer_grant(pending, 9.5))
        self.assertEqual(19, executor.active_deadline)

    def test_66_restart_same_epoch_different_authority_still_requires_proof(self) -> None:
        storage: dict[str, object] = {}
        executor = active_executor(sample_grant(), storage)
        executor.restart()
        restarted = Executor("member", storage)
        other = sample_grant("owner-b", "token-b", 2, "authority-b", 1)
        self.assertEqual("E_UNTRUSTED_AUTHORITY", restarted.offer_grant(other, 1))
        proof = AuthorityProof("authority-b", 1, True, True)
        self.assertEqual("E_UNTRUSTED_AUTHORITY", restarted.offer_grant(other, 1, proof))
        self.assertEqual("authority-a", storage["authority_id"])

    def test_67_restart_higher_authority_requires_proof_then_allows_switch(self) -> None:
        storage: dict[str, object] = {}
        executor = active_executor(sample_grant(), storage)
        executor.restart()
        restarted = Executor("member", storage)
        other = sample_grant("owner-b", "token-b", 2, "authority-b", 2)
        self.assertEqual("E_UNTRUSTED_AUTHORITY", restarted.offer_grant(other, 1))
        proof = AuthorityProof("authority-b", 2, True, True)
        self.assertEqual("E_PENDING_ACK", restarted.offer_grant(other, 1, proof))
        self.assertEqual("E_OK", restarted.confirm_activation(other.token, 1))
        self.assertEqual("E_OK", restarted.write(other, 1, "valid"))
        self.assertEqual("authority-b", storage["authority_id"])


if __name__ == "__main__":
    unittest.main()
