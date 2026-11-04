#!/usr/bin/env python3
"""Independent hashlib/hmac security vectors and C behavior differential."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


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


def c_vector(exe: pathlib.Path, name: str) -> dict[str, str | int]:
    text = subprocess.check_output([str(exe), "--vector", name], text=True, encoding="ascii").strip()
    result: dict[str, str | int] = {}
    for item in text.split():
        key, value = item.split("=", 1)
        result[key] = int(value) if key in {"valid", "wrong", "tamper"} else value
    print(f"C {name}: {len(text)} output bytes")
    return result


def did(vendor: int, serial: int) -> bytes:
    return vendor.to_bytes(2, "big") + serial.to_bytes(6, "big")


def derive(cred: bytes, nonce: bytes, a: bytes, b: bytes, txn: int,
           binding: int, session: int) -> bytes:
    first, second = sorted((a, b))
    prk = hmac.new(cred, b"IDCELL-AUTH-EXTRACT-V1" + nonce, hashlib.sha256).digest()
    info = (b"IDCELL-SESSION-KEY-V1" + first + second + txn.to_bytes(2, "big") +
            binding.to_bytes(4, "big") + session.to_bytes(8, "big") + b"\x01")
    return hmac.new(prk, info, hashlib.sha256).digest()


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def compare_kdf(c: dict[str, str | int], checks: Checks) -> None:
    cred = bytes(range(32))
    nonce = bytes(range(0xA0, 0xB0))
    a = did(0x0102, 0x030405060708)
    b = did(0x1112, 0x131415161718)
    other_did = did(0x2122, 0x232425262728)
    session = 0x0102030405060708
    key = derive(cred, nonce, a, b, 0x1234, 0, 0)
    rotated = derive(cred, nonce, a, b, 0x1234, 0x89ABCDEF, session)
    other = derive(cred, nonce, a, other_did, 0x1234, 0x89ABCDEF, session)
    reversed_key = derive(cred, nonce, b, a, 0x1234, 0x89ABCDEF, session)
    checks.eq(c["key"], key.hex().upper(), "HKDF-style pre-BIND key")
    checks.eq(c["rotated"], rotated.hex().upper(), "binding/session rotated key")
    checks.eq(c["other"], other.hex().upper(), "peer-separated key")
    checks.eq(reversed_key, rotated, "DID order normalized independently")
    checks.ok(key != rotated and rotated != other and key != cred, "session keys differ from peer/session/cred")
    key_id = hmac.new(rotated, b"IDCELL-KEY-ID-V1" + session.to_bytes(8, "big"), hashlib.sha256).digest()[:16]
    checks.eq(c["key_id"], key_id.hex().upper(), "key id derived without transmitting key")
    public_wire = bytes.fromhex(str(c["public_wire"]))
    authorized_wire = bytes.fromhex(str(c["authorized_wire"]))
    public_digest = hashlib.sha256(b"IDCELL-PUBLIC-DESC-V1" + public_wire).hexdigest().upper()
    authorized_digest = hashlib.sha256(b"IDCELL-AUTHORIZED-DESC-V1" + authorized_wire).hexdigest().upper()
    checks.eq(c["public"], public_digest, "independent public canonical digest")
    checks.eq(c["authorized"], authorized_digest, "independent authorized canonical digest")
    pos = 0
    while pos + 6 <= len(public_wire):
        size = int.from_bytes(public_wire[pos + 4:pos + 6], "big")
        pos += 6 + size
    checks.eq(pos, len(public_wire), "digest input is exact TLV length, not C struct padding")
    checks.ok(len(public_wire) < len(authorized_wire), "public descriptor is a strict subset")


def compare_wire(c: dict[str, str | int], checks: Checks) -> None:
    cred = bytes(range(32))
    nonce = bytes(range(0xA0, 0xB0))
    a = did(0x0102, 0x030405060708)
    b = did(0x1112, 0x131415161718)
    key = derive(cred, nonce, a, b, 0x1234, 0x89ABCDEF, 0x0102030405060708)
    payload = bytes((i * 7) & 0xFF for i in range(24))
    header = (b"\xA5\xA5\x0B\x00\x20\x08" + (0x2345).to_bytes(2, "big") +
              (0x3456).to_bytes(2, "big") + len(payload).to_bytes(2, "big") +
              a + b + (0x4567).to_bytes(2, "big") + (0xABCDEF010203).to_bytes(6, "big"))
    tag = hmac.new(key, header + payload, hashlib.sha256).digest()[:16]
    body = header + payload + tag
    expected = body + crc16(body).to_bytes(2, "big") + b"\x5A\xA5"
    wire = bytes.fromhex(str(c["wire"]))
    checks.eq(wire, expected, "independent Python frame/HMAC/CRC wire image")
    checks.eq(c["tag"], tag.hex().upper(), "independent truncated AUTH_TAG")
    checks.eq(c["valid"], 0, "C accepts Python-validated frame")
    checks.ok(not hmac.compare_digest(tag, hmac.new(b"\xA5" * 32, header + payload, hashlib.sha256).digest()[:16]),
              "Python independently detects wrong key")
    checks.eq(c["wrong"], -8, "C wrong-key behavior classification")
    mutated = bytearray(wire)
    mutated[36] ^= 1
    checks.ok(not hmac.compare_digest(tag, hmac.new(key, bytes(mutated[:36 + len(payload)]), hashlib.sha256).digest()[:16]),
              "Python independently detects payload tamper")
    checks.eq(c["tamper"], -8, "C tamper behavior classification")


class ReplayWindow:
    def __init__(self) -> None:
        self.valid = False
        self.max_seq = 0
        self.bitmap = 0

    def accept(self, seq: int) -> bool:
        if not self.valid:
            self.valid = True
            self.max_seq = seq
            self.bitmap = 1
            return True
        delta = (seq - self.max_seq) & 0xFFFF
        if delta == 0:
            return False
        if delta < 0x8000:
            self.bitmap = 1 if delta >= 64 else ((self.bitmap << delta) | 1) & 0xFFFFFFFFFFFFFFFF
            self.max_seq = seq
            return True
        age = (self.max_seq - seq) & 0xFFFF
        if age >= 64:
            return False
        bit = 1 << age
        if self.bitmap & bit:
            return False
        self.bitmap |= bit
        return True


def model_replay(seqs: list[int]) -> tuple[str, int, int]:
    window = ReplayWindow()
    accepted = "".join("1" if window.accept(seq) else "0" for seq in seqs)
    return accepted, window.max_seq, window.bitmap


def compare_replay(c: dict[str, str | int], checks: Checks) -> None:
    vectors = {
        "a": [100, 101, 99, 99, 38, 37, 102],
        "b": [65534, 65535, 0, 65533, 1, 65473, 65474, 0],
        "c": [0, 32768, 32767],
    }
    for name, seqs in vectors.items():
        accepted, max_seq, bitmap = model_replay(seqs)
        checks.eq(c[name], accepted, f"Python replay decisions {name}")
        checks.eq(int(c[f"{name}max"]), max_seq, f"Python replay max_seq {name}")
        checks.eq(int(c[f"{name}bits"], 16), bitmap, f"Python replay bitmap {name}")
    fresh = ReplayWindow()
    checks.eq(int(c["reset"]), int(fresh.accept(100)), "new session starts with an empty window")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=pathlib.Path,
                        default=ROOT / "build" / ("idcell-security-vectors.exe" if sys.platform == "win32"
                                                 else "idcell-security-vectors"))
    args = parser.parse_args()
    if not args.exe.is_file():
        raise SystemExit(f"missing C vector executable: {args.exe}; run build.ps1 first")
    exe = args.exe.resolve()
    checks = Checks()
    compare_kdf(c_vector(exe, "kdf"), checks)
    compare_wire(c_vector(exe, "wire"), checks)
    compare_replay(c_vector(exe, "replay"), checks)
    print(f"security differential PASS: {checks.count} checks across KDF/digest/wire/replay behavior")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
