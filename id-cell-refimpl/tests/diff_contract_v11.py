#!/usr/bin/env python3
"""C<->Python P0-3 high-level behavior differential; never modifies id-cell-sim."""
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
    text = subprocess.check_output([str(exe), "--vector", name], text=True, encoding="ascii").strip()
    result = {key: int(value) for key, value in (item.split("=") for item in text.split())}
    print(f"C {name}: {result}")
    return result


def expect(actual: dict[str, int], expected: dict[str, int], checks: list[str]) -> None:
    if actual != expected:
        raise AssertionError(f"expected {expected}, got {actual}")
    checks.extend(actual)


def python_schema() -> dict[str, int]:
    old = sim.Schema(sim.make_schema_id(7, 9), (sim.SchemaField("value", "f64", True),))
    new = sim.Schema(sim.make_schema_id(7, 10), (sim.SchemaField("value", "i16", True),))
    statuses = {
        "need": sim.check_schema_change(old, new, False, frozenset({"value"})),
        "allowed": sim.check_schema_change(old, new, True, frozenset({"value"})),
    }
    same = sim.Schema(old.schema_id, (sim.SchemaField("value", "i16", True),))
    statuses["same_id"] = sim.check_schema_change(old, same, True, frozenset({"value"}))
    unknown = sim.Schema(sim.make_schema_id(7, 11), (sim.SchemaField("unknown", "f64", True),))
    statuses["unknown"] = sim.check_schema_change(old, unknown, True, frozenset({"value"}))
    mapped = {"E_NEGOTIATE": 6, "E_OK": 0, "E_SCHEMA_ID": 13, "E_UNKNOWN_CRITICAL": 8}
    result = {key: mapped[status] for key, status in statuses.items()}
    result.update(f64_id=sim.make_schema_id(0, 1), i16_id=sim.make_schema_id(0, 2), f64_ns=0)
    return result


def prepared_manager() -> sim.BindingManager:
    key = b"contract-diff-key"
    manager = sim.BindingManager(key)
    schema = sim.Schema(1, (sim.SchemaField("value", "f64", True),))
    points = [sim.BindingPoint(1, "temperature")]
    caps = frozenset({"read", "write"})
    description, negotiation = b"descriptor", b"negotiation"
    proof = sim.bootstrap_proof(key, description, negotiation, "bind", points, caps,
                                {1: schema}, 5.0)
    assert manager.prepare("bind", points, caps, {1: schema}, frozenset({"value"}),
                           True, True, description, negotiation, proof, 5.0) == "E_OK"
    return manager


def python_bind() -> dict[str, int]:
    manager = prepared_manager()
    prepared_visible = int(manager.visible("bind"))
    manager.abort("bind")
    abort_visible = int(manager.visible("bind"))
    manager = prepared_manager()
    assert manager.commit("bind") == "E_OK"
    return {
        "prepared_visible": prepared_visible,
        "abort_visible": abort_visible,
        "commit_visible": int(manager.visible("bind")),
        "outside_rejected": int(manager.access("bind", "other") != "E_OK"),
    }


def python_mailbox() -> dict[str, int]:
    grant = sim.Grant("authority", 1, 1, "owner", 1, "token", 10)
    executor = sim.Executor("member")
    assert executor.offer_grant(grant, 0) == "E_PENDING_ACK"
    assert executor.confirm_activation(grant.token, 0) == "E_OK"
    mailbox = sim.Mailbox()
    context = sim.MailboxContext("binding", "session", executor)
    command = sim.MailboxCommand("one", 100, "binding", "session", grant, "write", 24)
    valid = mailbox.deliver(command, 1, context, True) == "E_OK"
    count = len(mailbox.executed)
    duplicate = mailbox.deliver(command, 1, context, True) == "E_OK" and len(mailbox.executed) == count
    conflict = (mailbox.deliver(replace(command, value=25), 1, context, True) == "E_COMMAND_CONFLICT"
                and len(mailbox.executed) == count)
    expired_cmd = sim.MailboxCommand("two", 0, "binding", "session", grant, "write", 24)
    expired = (mailbox.deliver(expired_cmd, 1, context, True) == "E_EXPIRED"
               and len(mailbox.executed) == count)
    old_session = replace(command, command_id="three", session_id="old")
    old_session_rejected = (mailbox.deliver(old_session, 1, context, True) == "E_SESSION"
                            and len(mailbox.executed) == count)
    old_epoch = replace(command, command_id="four", grant=replace(grant, grant_epoch=0))
    old_epoch_rejected = mailbox.deliver(old_epoch, 1, context, True) != "E_OK" and len(mailbox.executed) == count
    return {
        "valid": 0 if valid else -1,
        "duplicate": 0 if duplicate else -1,
        "conflict": 13 if conflict else -1,
        "expired": 9 if expired else -1,
        # Executor 拒绝旧上下文；请求方对旧 session/epoch 的异步 ERROR 再做关联过滤，不交付（-1）。
        "old_session": -1 if old_session_rejected else 0,
        "old_epoch": -1 if old_epoch_rejected else 0,
    }


def python_restart() -> dict[str, int]:
    storage: dict[str, object] = {}
    grant = sim.Grant("authority", 1, 1, "owner", 1, "token", 10)
    executor = sim.Executor("member", storage)
    assert executor.offer_grant(grant, 0) == "E_PENDING_ACK"
    assert executor.confirm_activation(grant.token, 0) == "E_OK"
    executor.restart()
    old_rejected = executor.validate_write(grant, 1) != "E_OK"
    low_rejected = executor.offer_grant(replace(grant, grant_epoch=0), 1) == "E_STALE_EPOCH"
    new = replace(grant, grant_epoch=2, token="new")
    offered = executor.offer_grant(new, 1) == "E_PENDING_ACK"
    activated = executor.confirm_activation(new.token, 1) == "E_OK"
    mailbox = sim.Mailbox()
    old_command = sim.MailboxCommand("old", 100, "old-binding", "old-session", grant, "write", 26)
    old_status = mailbox.deliver(
        old_command, 1, sim.MailboxContext("new-binding", "new-session", executor), True,
    )
    new_command = sim.MailboxCommand("new", 100, "new-binding", "new-session", new, "write", 27)
    new_status = mailbox.deliver(
        new_command, 1, sim.MailboxContext("new-binding", "new-session", executor), True,
    )
    return {
        # 重启同时清除会话密钥：旧帧在 ERROR 产生前即 fail-closed，异步接收侧忽略为 -1。
        "old_rejected": -1 if old_rejected and low_rejected else 0,
        "higher": int(offered and activated),
        # 当前 B 不接收旧 A 的 ERROR；Python mailbox 对应 E_BINDING，异步接收侧忽略为 -1。
        "old_epoch_rejected": -1 if old_status == "E_BINDING" else 0,
        "new_executed": 0 if new_status == "E_OK" else -1,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=pathlib.Path,
                        default=ROOT / "build" / ("idcell-contract-vectors.exe" if sys.platform == "win32"
                                                 else "idcell-contract-vectors"))
    args = parser.parse_args()
    if not args.exe.is_file():
        raise SystemExit(f"missing C vector executable: {args.exe}; run build.ps1 first")
    checks: list[str] = []
    expect(c_vector(args.exe.resolve(), "schema"), python_schema(), checks)
    expect(c_vector(args.exe.resolve(), "bind"), python_bind(), checks)
    expect(c_vector(args.exe.resolve(), "mailbox"), python_mailbox(), checks)
    expect(c_vector(args.exe.resolve(), "restart"), python_restart(), checks)
    print(f"contract differential PASS: {len(checks)} checks across 4 behavior groups")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
