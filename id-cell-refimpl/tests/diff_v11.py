#!/usr/bin/env python3
"""C<->Python v0.11 frame differential tests; never modifies id-cell-sim."""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIM_DIR = ROOT.parent / "id-cell-sim"
sys.path.insert(0, str(SIM_DIR))

import idcell_sim as sim  # noqa: E402
import test_idcell_sim as sim_test  # noqa: E402


class Differential:
    def __init__(self, executable: pathlib.Path) -> None:
        self.proc = subprocess.Popen(
            [str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, encoding="ascii", bufsize=1,
        )
        self.checks = 0

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        rc = self.proc.wait(timeout=10)
        if rc != 0:
            raise RuntimeError(f"C vector process exited with {rc}")

    def call(self, command: str) -> list[str]:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(f"C vector process closed stdout for: {command}")
        return line.strip().split()

    def eq(self, actual: object, expected: object, name: str) -> None:
        self.checks += 1
        if actual != expected:
            raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")

    def encode_c(self, frame: sim.Frame, key: bytes = b"") -> bytes:
        fields = [
            "ENCODE", key.hex() or "-", hex(frame.ver), hex(frame.prof), hex(frame.flags),
            hex(frame.frame_type), hex(frame.seq), hex(frame.txn),
            frame.src.to_bytes(8, "big").hex(), frame.dst.to_bytes(8, "big").hex(),
            hex(frame.group), hex(frame.ts), frame.payload.hex() or "-",
        ]
        result = self.call(" ".join(fields))
        self.eq(result[0], "OK", "C encode succeeds")
        return bytes.fromhex(result[1])

    def decode_c(self, wire: bytes, key: bytes = b"") -> dict[str, object] | str:
        result = self.call(f"DECODE {key.hex() or '-'} {wire.hex() or '-'}")
        if result[0] == "ERR":
            return result[1]
        self.eq(result[0], "OK", "C decode succeeds")
        return {
            "status": result[1], "consumed": int(result[2]), "ver": int(result[3], 0),
            "prof": int(result[4], 0), "flags": int(result[5], 0),
            "frame_type": int(result[6], 0), "seq": int(result[7], 0),
            "txn": int(result[8], 0), "payload_len": int(result[9]),
            "src": bytes.fromhex(result[10]), "dst": bytes.fromhex(result[11]),
            "group": int(result[12], 0), "ts": int(result[13], 0),
            "payload": b"" if result[14] == "-" else bytes.fromhex(result[14]),
            "auth_tag": b"" if result[15] == "-" else bytes.fromhex(result[15]),
        }

    def python_one(self, wire: bytes, key: bytes = b"") -> sim.ParseResult:
        results = sim.StreamParser(key=key, max_payload=1460).feed(wire)
        if len(results) != 1:
            raise AssertionError(f"expected one Python result, got {results!r}")
        return results[0]

    def compare_decode(self, wire: bytes, key: bytes, name: str) -> dict[str, object]:
        py = self.python_one(wire, key)
        c = self.decode_c(wire, key)
        if not isinstance(c, dict):
            raise AssertionError(f"{name}: C returned {c}, Python returned {py.status}")
        expected_status = "OK_RT" if py.frame and py.frame.prof == sim.PROF_RT else "OK_STD"
        self.eq(c["status"], expected_status, name + " status")
        frame = py.frame
        assert frame is not None
        expected = {
            "consumed": len(wire), "ver": frame.ver, "prof": frame.prof, "flags": frame.flags,
            "frame_type": frame.frame_type, "seq": frame.seq, "txn": frame.txn,
            "payload_len": len(frame.payload), "src": frame.src.to_bytes(8, "big"),
            "dst": frame.dst.to_bytes(8, "big"), "group": frame.group, "ts": frame.ts,
            "payload": frame.payload, "auth_tag": frame.auth_tag,
        }
        for field, value in expected.items():
            self.eq(c[field], value, f"{name} decoded {field}")
        return c

    def compare_error(self, wire: bytes, key: bytes, expected: str, name: str) -> None:
        # C decode 只报告当前帧的首个结果；Python 可能继续报告后续垃圾字节。
        results = sim.StreamParser(key=key, max_payload=1460).feed(wire)
        if expected == "NEED_MORE" and not results:
            # 单独一个 0xA5 只保留半 SYNC；语义同为等待更多字节。
            py_status = "NEED_MORE"
        else:
            if not results:
                raise AssertionError(f"{name}: Python returned no result")
            py_status = results[0].status
        c = self.decode_c(wire, key)
        self.eq((c, py_status), (expected, expected), name)

    def encode_and_decode(self, frame: sim.Frame, key: bytes, name: str) -> bytes:
        py_wire = sim.encode_frame(frame, key)
        c_wire = self.encode_c(frame, key)
        self.eq(c_wire, py_wire, name + " exact wire")
        self.compare_decode(py_wire, key, name + " Python wire -> C")
        self.compare_decode(c_wire, key, name + " C wire -> C/Python fields")
        return c_wire


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--exe", type=pathlib.Path,
        default=ROOT / "build" / ("idcell-v11-vectors.exe" if sys.platform == "win32" else "idcell-v11-vectors"),
    )
    args = parser.parse_args()
    if not args.exe.is_file():
        raise SystemExit(f"missing C vector executable: {args.exe}; run build.ps1 first")

    diff = Differential(args.exe.resolve())
    try:
        noauth = diff.encode_and_decode(sim_test.golden_frame(False), b"", "golden no-AUTH")
        diff.eq(noauth, sim_test.GOLDEN_NOAUTH, "sim golden no-AUTH constant")
        auth = diff.encode_and_decode(sim_test.golden_frame(True), sim_test.GOLDEN_KEY, "golden AUTH")
        diff.eq(auth, sim_test.GOLDEN_AUTH, "sim golden AUTH constant")
        diff.eq((sim.TYPE_READ, sim.TYPE_WRITE, sim.TYPE_AUTH, sim.TYPE_BIND), (8, 9, 6, 7),
                "Python TYPE semantics match C enum values")
        diff.eq((noauth[5], auth[5]), (8, 9), "golden TYPE bytes are READ=8/WRITE=9")
        print("[PASS] two complete golden vectors match byte-for-byte in both directions")

        rt = sim.Frame(
            payload=bytes(range(256)), prof=sim.PROF_RT, flags=sim.AUTH_FLAG,
            frame_type=sim.TYPE_READ, seq=0x1234, txn=0x5678,
            src=0x0102030405060708, dst=0x1112131415161718,
            group=0x2222, ts=0xABCDEF010203,
        )
        diff.encode_and_decode(rt, b"rt-full-payload-key", "AUTH RT arbitrary payload")
        raw = sim.Frame(
            payload=b"\x5a\xa5\x00\xa5\xa5" + bytes(range(32)), frame_type=sim.TYPE_READ,
            seq=9, txn=10, src=11, dst=12, group=13, ts=14,
        )
        diff.encode_and_decode(raw, b"", "STD payload containing marker bytes")
        print("[PASS] STD/RT and full-payload authentication are profile-driven")

        for label, wire, key in (("no-AUTH", noauth, b""), ("AUTH", auth, sim_test.GOLDEN_KEY)):
            for cut in range(1, len(wire)):
                diff.compare_error(wire[:cut], key, "NEED_MORE", f"{label} truncation at {cut}")
        print("[PASS] every truncation prefix has identical NEED_MORE classification")

        crc_at = len(noauth) - 4
        mutated = bytearray(noauth)
        mutated[10:12] = b"\xff\xff"
        diff.compare_error(bytes(mutated), b"", "BAD_LENGTH", "oversize LEN")
        mutated = bytearray(noauth)
        mutated[-1] ^= 1
        diff.compare_error(bytes(mutated), b"", "BAD_TRAILER", "bad TRAILER")
        mutated = bytearray(noauth)
        mutated[crc_at] ^= 1
        diff.compare_error(bytes(mutated), b"", "BAD_CRC", "bad CRC")
        mutated = bytearray(auth)
        mutated[39] ^= 1
        diff.compare_error(sim_test.recrc(bytes(mutated)), sim_test.GOLDEN_KEY, "BAD_AUTH", "bad HMAC with valid CRC")
        diff.compare_error(auth, b"wrong-key", "BAD_AUTH", "wrong HMAC key")
        mutated = bytearray(noauth)
        mutated[0] ^= 1
        diff.compare_error(bytes(mutated), b"", "BAD_SYNC", "bad SYNC")
        mutated = bytearray(noauth)
        mutated[2] = 0x10
        diff.compare_error(sim_test.recrc(bytes(mutated)), b"", "BAD_VERSION", "bad major version")
        mutated = bytearray(noauth)
        mutated[3] = 2
        diff.compare_error(sim_test.recrc(bytes(mutated)), b"", "BAD_PROFILE", "bad profile")
        mutated = bytearray(noauth)
        mutated[5] = 0xFF
        diff.compare_error(sim_test.recrc(bytes(mutated)), b"", "BAD_TYPE", "unknown TYPE with valid CRC")
        for offset in (6, 12, 20, 30, 39):
            mutated = bytearray(auth)
            mutated[offset] ^= 1
            diff.compare_error(
                sim_test.recrc(bytes(mutated)), sim_test.GOLDEN_KEY, "BAD_AUTH",
                f"AUTH protected offset {offset}",
            )
        print("[PASS] LEN/CRC/HMAC/TRAILER/SYNC/version/profile/TYPE error classes match")

        joined = noauth + auth
        py_results = sim.StreamParser(key=sim_test.GOLDEN_KEY, max_payload=1460).feed(joined)
        diff.eq([r.status for r in py_results], ["OK_STD", "OK_STD"], "Python coalesced frames")
        first = diff.decode_c(joined, sim_test.GOLDEN_KEY)
        assert isinstance(first, dict)
        diff.eq(first["consumed"], len(noauth), "C coalesced first consumed length")
        diff.compare_decode(joined[len(noauth):], sim_test.GOLDEN_KEY, "C coalesced second frame")
        print(f"v0.11 differential PASS: {diff.checks} checks")
        return 0
    finally:
        diff.close()


if __name__ == "__main__":
    raise SystemExit(main())
