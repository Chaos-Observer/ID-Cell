#!/usr/bin/env python3
"""C<->Python P1-1 discovery/presence/suspended behavior differential."""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
from dataclasses import replace

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIM_DIR = ROOT.parent / "id-cell-sim"
sys.path.insert(0, str(SIM_DIR))
import idcell_sim as sim  # noqa: E402


def c_vector(exe: pathlib.Path, name: str) -> dict[str, int]:
    text = subprocess.check_output([str(exe), "--vector", name], text=True, encoding="ascii")
    result = {key: int(value) for key, value in
              (item.split("=") for item in text.split())}
    print(f"C {name}: {result}")
    return result


class Checks:
    def __init__(self) -> None:
        self.count = 0

    def eq(self, actual: object, expected: object, name: str) -> None:
        self.count += 1
        if actual != expected:
            raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")

    def ok(self, condition: bool, name: str) -> None:
        self.count += 1
        if not condition:
            raise AssertionError(name)


def compare_announce(c: dict[str, int], checks: Checks) -> None:
    events = sim.EventQueue()
    py = sim.AnnounceScheduler(events, 1, seed=19, base=2, retry_max=5,
                               period=20, initial_jitter=3)
    py.start()
    checks.ok(0 <= c["initial"] <= 3, "C initial jitter is within configured interval")
    checks.ok(0.0 <= py.next_delay <= 3, "Python initial jitter is within configured interval")
    events.run_until(100)
    checks.ok(c["retry_max"] <= 5, "C unconfirmed delay never exceeds cap")
    py_max = max((b - a for a, b in zip(py.announcements, py.announcements[1:])), default=0)
    checks.ok(py_max <= 5, "Python unconfirmed delay never exceeds cap")
    checks.eq(c["empty_confirmed"], 0, "empty HELLO is not confirmation in C")
    checks.eq(int(py.confirmed), 0, "Python scheduler starts unconfirmed")
    py.confirm()
    checks.eq(c["confirmed"], int(py.confirmed), "valid response confirmation state")
    checks.eq(c["failures"], 0, "C resets failure count after confirmation")
    checks.eq(c["steady1"], py.period, "first confirmed steady period")
    checks.eq(c["steady2"], py.period, "second confirmed steady period")


def compare_discovery(c: dict[str, int], checks: Checks) -> None:
    errors = {"E_OK": 0, "E_SCOPE": 14, "E_UNAVAILABLE": 15, "E_DUPLICATE": 16}
    py = sim.DiscoveryAgent(cache_capacity=2, cache_ttl=100, scope="default")
    outside = py.receive_probe(sim.Probe(1, 1, 2, scope="other"), now=0)
    checks.eq(c["scope"], errors[outside.response_status], "scope error")
    first = py.receive_probe(sim.Probe(1, 1, 2), now=1)
    duplicate = py.receive_probe(sim.Probe(1, 1, 1), now=2)
    checks.eq(c["duplicate"], errors[duplicate.response_status], "dual-path duplicate error")
    checks.eq(c["dual_fetches"], py.descriptor_fetches, "dual-path descriptor fetch count")
    checks.eq(c["hop1_forward"], first.forwarded.hop_limit, "forwarded hop limit")
    terminal = py.receive_probe(sim.Probe(1, 2, 0), now=3)
    checks.eq(c["hop0_forward"], 0 if terminal.forwarded is None else 1, "hop-zero forward event count")
    checks.eq(c["cache_size"], py.cache_size, "bounded cache size")

    unavailable_agent = sim.DiscoveryAgent(cache_capacity=2)
    unavailable = unavailable_agent.receive_probe(sim.Probe(1, 9, 0), descriptor_available=False, now=0)
    checks.eq(c["unavailable"], errors[unavailable.response_status], "descriptor unavailable error")
    checks.eq(c["unavailable_cache"], unavailable_agent.cache_size,
              "relay-processed unavailable query retains nonterminal dedup")
    recovered = unavailable_agent.receive_probe(sim.Probe(1, 9, 0), descriptor_available=True, now=1)
    checks.eq(c["recovered"], errors[recovered.response_status], "same query recovery status")
    checks.eq(c["recovered_fetches"], unavailable_agent.descriptor_fetches,
              "recovery descriptor fetch count")


def compare_relay(c: dict[str, int], checks: Checks) -> None:
    py = sim.DiscoveryAgent(node_id=99)
    probe = sim.Probe(1, 30, 2, "temperature", target_id=20, src_id=10, dst_id=20)
    forwarded = py.receive_probe(probe, descriptor_available=False).forwarded
    checks.eq(c["relay_src"], c["origin_low"], "C relay preserves numeric source DID")
    checks.eq(c["relay_dst"], c["target_low"], "C relay preserves numeric destination DID")
    checks.eq(forwarded.src_id, 10, "Python relay preserves source DID")
    checks.eq(forwarded.dst_id, 20, "Python relay preserves destination DID")
    checks.eq(c["relay_hop"], forwarded.hop_limit, "relay hop decrement")
    checks.eq(py.descriptor_fetches, 0, "Python pure relay performs no descriptor read")
    failed = py.receive_probe(sim.Probe(1, 31, 1), descriptor_available=False, forward_ok=False)
    checks.eq(c["send_fault"], 8 if failed.response_status == "E_SEND" else -1,
              "forward send fault error mapping")
    checks.eq(c["fault_cache"], int((1, 31) in py.seen), "failed forward leaves no terminal dedup")
    capable = sim.DiscoveryAgent(node_id=1, capability_labels=("temperature",), model="p1-node")
    elsewhere = capable.receive_probe(sim.Probe(1, 32, 1, "temperature", target_id=2))
    checks.eq(c["target_fetch"], capable.descriptor_fetches, "target-other suppresses descriptor read")
    checks.ok(elsewhere.forwarded is not None, "Python target-other still forwards")
    capable.receive_probe(sim.Probe(1, 33, 0, "nonexistent"))
    checks.eq(c["query_fetch"], capable.descriptor_fetches, "nonexistent query suppresses descriptor read")


def compare_presence(c: dict[str, int], checks: Checks) -> None:
    states = {"ONLINE": 0, "ASLEEP": 1, "OFFLINE": 2}
    ordinary = sim.Presence(heartbeat=5)
    ordinary.receive_valid(0)
    checks.eq(c["ordinary_before"], states[ordinary.state(14)], "ordinary online before timeout")
    checks.eq(c["ordinary_offline"], states[ordinary.state(15)], "ordinary three-heartbeat offline")
    scheduled = sim.Presence(5, scheduled_period=20, max_wake_latency=30)
    scheduled.receive_valid(20)
    scheduled.sleep()
    checks.eq(c["scheduled_asleep"], states[scheduled.state(49)], "scheduled asleep state")
    checks.eq(c["scheduled_offline"], states[scheduled.state(50)], "scheduled maximum-wake offline")
    checks.eq("CHECK_IN", scheduled.wake(51), "wake emits CHECK-IN")
    checks.eq(c["recovered"], states[scheduled.state(51)], "CHECK-IN restores online state")
    scheduled.offline()
    checks.eq(c["explicit_offline"], states[scheduled.state(52)], "explicit OFFLINE state")
    scheduled.receive_ordinary(53)
    checks.eq(c["ordinary_after_offline"], states[scheduled.state(53)], "ordinary frame stays OFFLINE")
    checks.eq(c["empty_after_offline"], states[scheduled.state(53)], "empty HELLO stays OFFLINE")
    scheduled.receive_valid(55)
    checks.eq(c["checkin_after_offline"], states[scheduled.state(55)], "valid CHECK-IN resumes OFFLINE")


def compare_mailbox(c: dict[str, int], checks: Checks) -> None:
    old_grant = sim.Grant("authority", 1, 1, "owner", 1, "token", 1000)
    old_executor = sim.Executor("member")
    assert old_executor.offer_grant(old_grant, 0) == "E_PENDING_ACK"
    assert old_executor.confirm_activation(old_grant.token, 0) == "E_OK"
    mailbox = sim.Mailbox()
    context = sim.MailboxContext("binding", "session", old_executor)
    old = sim.MailboxCommand("old", 500, "binding", "session", old_grant, "write", 24)
    context.suspend()
    checks.eq(c["suspended"], int(context.suspended), "sleep immediately suspends context")
    checks.eq(mailbox.deliver(old, 1, context, True), "E_SUSPENDED", "Python suspended write rejected")
    checks.eq(c["wake_executed"], len(mailbox.executed), "no old FIFO execution before activation")
    context.wake()
    checks.eq(c["recovery"], int(context.recovery), "wake forces recovery state")
    new_grant = replace(old_grant, grant_epoch=2, authority_epoch=2, member_epoch=2, token="new")
    new_executor = sim.Executor("member")
    assert new_executor.offer_grant(new_grant, 1) == "E_PENDING_ACK"
    assert new_executor.confirm_activation(new_grant.token, 1) == "E_OK"
    context.activate("new-binding", "new-session", new_executor)
    checks.eq(c["reactivated"], int(not context.suspended and not context.recovery),
              "new session/grant activation state")
    old_status = mailbox.deliver(old, 2, context, True)
    checks.eq(c["old_after"], -1 if old_status == "E_BINDING" else 0,
              "old context remains rejected after activation")
    command = sim.MailboxCommand("new", 500, "new-binding", "new-session", new_grant, "write", 24)
    valid = mailbox.deliver(command, 2, context, True)
    duplicate = mailbox.deliver(command, 2, context, True)
    expired_command = replace(command, command_id="expired", not_after=0)
    expired = mailbox.deliver(expired_command, 2, context, True)
    old_session = mailbox.deliver(replace(command, command_id="old-session", session_id="old"),
                                  2, context, True)
    old_epoch = mailbox.deliver(replace(command, command_id="old-epoch",
                                        grant=replace(new_grant, grant_epoch=0)), 2, context, True)
    nan = mailbox.deliver(replace(command, command_id="nan", value=float("nan")), 2, context, True)
    checks.eq(c["valid"], 0 if valid == "E_OK" else -1, "new-context write status")
    checks.eq(c["duplicate"], 0 if duplicate == "E_OK" else -1, "duplicate completion status")
    checks.eq(c["expired"], 9 if expired == "E_EXPIRED" else -1, "expired command error")
    checks.eq(c["old_session"], -1 if old_session == "E_SESSION" else 0, "old session rejection")
    checks.eq(c["old_epoch"], -1 if old_epoch != "E_OK" else 0, "old epoch rejection")
    checks.eq(c["nan"], 10 if nan == "E_RANGE" else -1, "NaN range error")
    checks.eq(c["executed"], len(mailbox.executed), "exactly one new-context side effect")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=pathlib.Path,
                        default=ROOT / "build" / ("idcell-discovery-vectors.exe" if sys.platform == "win32"
                                                 else "idcell-discovery-vectors"))
    args = parser.parse_args()
    if not args.exe.is_file():
        raise SystemExit(f"missing C vector executable: {args.exe}; run build.ps1 first")
    exe = args.exe.resolve()
    checks = Checks()
    compare_announce(c_vector(exe, "announce"), checks)
    compare_discovery(c_vector(exe, "discovery"), checks)
    compare_relay(c_vector(exe, "relay"), checks)
    compare_presence(c_vector(exe, "presence"), checks)
    compare_mailbox(c_vector(exe, "mailbox"), checks)
    print(f"discovery differential PASS: {checks.count} checks across 5 behavior groups")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
