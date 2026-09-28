"""Black-box Linux tests; all mutable fixtures live in an isolated /tmp directory."""
import fcntl
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fia-test-")
        self.base = Path(self.temp.name)
        self.root = self.base / "protected files"
        self.root.mkdir()
        self.state = self.base / "state"
        (self.root / "alpha.txt").write_text("original\n")

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, *args, code=0, state=None):
        result = subprocess.run([BINARY, *map(str, args), "--state", str(state or self.state)],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def init(self):
        return self.run_cli("init", self.root)

    def test_scan_and_metadata(self):
        (self.root / "gone").write_text("delete me")
        (self.root / "mode").write_text("permission")
        (self.root / "touch").write_text("mtime")
        self.init()
        self.assertIn("UNCHANGED", self.run_cli("scan", "--all"))
        (self.root / "alpha.txt").write_text("modified\n")
        (self.root / "gone").unlink()
        (self.root / "new\tline\nfile").write_bytes(b"\x00\xffbinary")
        os.chmod(self.root / "mode", 0o400)
        info = (self.root / "touch").stat()
        os.utime(self.root / "touch", ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
        output = self.run_cli("scan", code=2)
        for event in ("MODIFIED", "DELETED", "NEW", "PERMISSION_CHANGE", "METADATA_CHANGE"):
            self.assertIn("[" + event + "]", output)
        report = self.run_cli("report")
        self.assertIn(hashlib.sha256(b"modified\n").hexdigest(), report)
        self.assertIn("new\\x09line\\x0afile", report)
        self.run_cli("verify-log")
        self.assertIn("Baseline files: 4", self.run_cli("status"))
        self.run_cli("scan", code=2)  # Baseline remains immutable.

    def test_symlinks_special_files_and_binary_hash(self):
        (self.root / "external").symlink_to("/etc/passwd")
        (self.root / "loop").symlink_to(self.root, target_is_directory=True)
        os.mkfifo(self.root / "fifo")
        payload = bytes(range(256)) * 800
        (self.root / "binary").write_bytes(payload)
        self.assertIn("2 files", self.init())
        self.assertIn(hashlib.sha256(payload).hexdigest(), self.run_cli("scan", "--all"))

    def test_log_tampering_and_checkpoint(self):
        self.init()
        self.run_cli("scan")
        log = self.state / "audit.log"
        original = log.read_bytes()
        head = self.run_cli("verify-log").split("Log head: ")[1].strip()
        self.run_cli("verify-log", "--expect-head", head)
        log.write_bytes(original.replace(b"SCAN", b"SCAM", 1))
        self.assertIn("invalid", self.run_cli("verify-log", code=1))
        self.run_cli("scan", code=1)
        self.assertEqual(log.read_bytes(), original.replace(b"SCAN", b"SCAM", 1))
        log.write_bytes(original[:-1])
        self.run_cli("verify-log", code=1)
        log.write_bytes(b"\n".join(original.split(b"\n")[:-2]) + b"\n")
        self.run_cli("verify-log")  # An unanchored valid prefix cannot reveal suffix removal.
        self.assertIn("checkpoint", self.run_cli("verify-log", "--expect-head", head, code=1))
        log.write_bytes(original)
        lines = original.splitlines(keepends=True)
        log.write_bytes(lines[0] + lines[2] + lines[1])
        self.run_cli("verify-log", code=1)

    def test_baseline_corruption_and_binding(self):
        self.init()
        file = self.state / "baseline.dat"
        original = file.read_bytes()
        file.write_bytes(original.replace(b"FIA_BASELINE", b"BAD_BASELINE"))
        self.assertIn("checksum", self.run_cli("scan", code=1))
        payload = original[:original.rfind(b"CHECKSUM\t")]
        old_hash = hashlib.sha256(b"original\n").hexdigest().encode()
        payload = payload.replace(old_hash, b"0" * 64)
        file.write_bytes(payload + b"CHECKSUM\t" + hashlib.sha256(payload).hexdigest().encode() + b"\n")
        self.assertIn("INIT", self.run_cli("scan", code=1))

    def test_validation_and_locking(self):
        self.run_cli("init", self.root, state=self.root / "state", code=1)
        self.assertFalse((self.root / "state").exists())
        self.init()
        original = (self.state / "baseline.dat").read_bytes()
        self.run_cli("init", self.root, code=1)
        self.assertEqual(original, (self.state / "baseline.dat").read_bytes())
        other = self.base / "other"
        other.mkdir()
        self.run_cli("scan", other, code=1)
        self.run_cli("scan", "--duration", "1", code=1)
        self.run_cli("monitor", "--duration", "0", code=1)
        with (self.state / "lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIn("busy", self.run_cli("scan", code=1))
        (self.state / "audit.log").unlink()
        self.run_cli("verify-log", code=1)

    def test_empty_tree(self):
        (self.root / "alpha.txt").unlink()
        self.assertIn("0 files", self.init())
        self.run_cli("scan")

    def wait_event(self, event, encoded_path=None, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            records = (self.state / "audit.log").read_text().splitlines()[1:]
            for row in records:
                fields = row.split("\t")
                if len(fields) == 10 and fields[2] == event and (encoded_path is None or fields[3] == encoded_path):
                    return
            time.sleep(0.05)
        self.fail(f"Timed out waiting for {event} {encoded_path}")

    def event_records(self):
        records = []
        for line in (self.state / "audit.log").read_text().splitlines()[1:]:
            fields = line.split("\t")
            if len(fields) == 10:
                records.append({"type": fields[2], "path": bytes.fromhex(fields[3]).decode(),
                                "old": fields[4], "new": fields[5],
                                "detail": bytes.fromhex(fields[6]).decode()})
        return records

    @contextmanager
    def monitored(self):
        with (self.base / "regression-monitor.out").open("w+") as output:
            process = subprocess.Popen([BINARY, "monitor", "--state", str(self.state)],
                                       stdout=output, stderr=output)
            try:
                self.wait_event("MONITOR_START")
                yield process
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGCONT)
                    process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                output.seek(0)
                self.assertEqual(process.returncode, 0, output.read())

    @contextmanager
    def paused_monitor(self, process):
        process.send_signal(signal.SIGSTOP)
        os.waitpid(process.pid, os.WUNTRACED)
        try:
            yield
        finally:
            process.send_signal(signal.SIGCONT)

    def test_rapid_file_rename_chain(self):
        (self.root / "a").write_text("AAA")
        (self.root / "b").write_text("BBB")
        self.init()
        with self.monitored() as process:
            with self.paused_monitor(process):
                (self.root / "a").rename(self.root / "b")
                (self.root / "b").rename(self.root / "c")
            self.wait_event("MOVE", b"c".hex())
        moves = [event for event in self.event_records() if event["type"] == "MOVE"]
        self.assertEqual([event["path"] for event in moves], ["b", "c"])
        moved_hash = hashlib.sha256(b"AAA").hexdigest()
        self.assertEqual([event["old"] for event in moves], [moved_hash, moved_hash])
        self.assertEqual(moves[0]["new"], "-")  # Intermediate contents were not sampled.
        self.assertEqual(moves[1]["new"], moved_hash)
        self.assertIn("replaced_hash=" + hashlib.sha256(b"BBB").hexdigest(), moves[0]["detail"])
        self.run_cli("verify-log")

    def test_rapid_directory_then_child_rename(self):
        (self.root / "d").mkdir()
        (self.root / "d" / "f").write_text("child")
        self.init()
        with self.monitored() as process:
            with self.paused_monitor(process):
                (self.root / "d").rename(self.root / "e")
                (self.root / "e" / "f").rename(self.root / "e" / "g")
            self.wait_event("MOVE", b"e/g".hex())
            (self.root / "e" / "g").write_text("still monitored")
            self.wait_event("MODIFIED", b"e/g".hex())
        records = self.event_records()
        moves = [event for event in records if event["type"] == "MOVE"]
        self.assertEqual([event["path"] for event in moves], ["e", "e/g"])
        self.assertEqual(moves[1]["detail"], 'from="e/f"')
        child_hash = hashlib.sha256(b"child").hexdigest()
        self.assertEqual((moves[1]["old"], moves[1]["new"]), (child_hash, child_hash))
        self.assertFalse(any(event["type"] in ("NEW", "DELETED") for event in records))
        self.run_cli("verify-log")

    def test_single_file_rename_hashes(self):
        self.init()
        with self.monitored():
            (self.root / "alpha.txt").rename(self.root / "renamed.txt")
            self.wait_event("MOVE", b"renamed.txt".hex())
        moves = [event for event in self.event_records() if event["type"] == "MOVE"]
        self.assertEqual(len(moves), 1)
        expected = hashlib.sha256(b"original\n").hexdigest()
        self.assertEqual((moves[0]["path"], moves[0]["detail"], moves[0]["old"], moves[0]["new"]),
                         ("renamed.txt", 'from="alpha.txt"', expected, expected))

    def test_single_directory_rename_keeps_watch(self):
        (self.root / "d").mkdir()
        (self.root / "d" / "f").write_text("child")
        self.init()
        with self.monitored():
            (self.root / "d").rename(self.root / "e")
            self.wait_event("MOVE", b"e".hex())
            (self.root / "e" / "f").write_text("updated")
            self.wait_event("MODIFIED", b"e/f".hex())
        records = self.event_records()
        moves = [event for event in records if event["type"] == "MOVE"]
        self.assertEqual(len(moves), 1)
        self.assertEqual((moves[0]["path"], moves[0]["detail"]), ("e", 'from="d"'))
        self.assertFalse(any(event["type"] in ("NEW", "DELETED") for event in records))

    def wait_for_state_lock(self, process, timeout=5):
        # Linux exposes the blocked syscall's wait channel. This synchronizes the
        # test with real lock contention instead of guessing when append starts.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.assertIsNone(process.poll(), "Monitor exited while waiting for state lock")
            channel = Path(f"/proc/{process.pid}/wchan").read_text().strip()
            if "lock" in channel:
                return
            time.sleep(0.02)
        self.fail("Monitor did not block on the held state lock")

    def test_monitor_waits_for_state_lock(self):
        self.init()
        with self.monitored() as process:
            with (self.state / "lock").open("r+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                (self.root / "alpha.txt").write_text("change while state is busy")
                self.wait_for_state_lock(process)
                self.assertFalse(any(event["type"] == "MODIFIED" for event in self.event_records()))
            self.wait_event("MODIFIED", b"alpha.txt".hex())
            self.assertIsNone(process.poll())
        records = self.event_records()
        modified = [event for event in records if event["type"] == "MODIFIED"]
        self.assertEqual(len(modified), 1)
        self.assertEqual(modified[0]["new"], hashlib.sha256(b"change while state is busy").hexdigest())
        self.assertEqual(records[-1]["type"], "MONITOR_STOP")
        self.run_cli("verify-log")

    def test_monitor_preserves_pending_append_on_signal(self):
        self.init()
        with self.monitored() as process:
            with (self.state / "lock").open("r+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                (self.root / "alpha.txt").write_text("pending at shutdown")
                self.wait_for_state_lock(process)
                process.send_signal(signal.SIGTERM)
                time.sleep(0.1)
                self.assertIsNone(process.poll(), "Pending append was abandoned on SIGTERM")
            process.wait(timeout=5)
        records = self.event_records()
        self.assertEqual([event["type"] for event in records],
                         ["INIT", "MONITOR_START", "MODIFIED", "MONITOR_STOP"])
        self.assertEqual(records[2]["new"], hashlib.sha256(b"pending at shutdown").hexdigest())
        self.run_cli("verify-log")

    def test_unsafe_existing_state_permissions(self):
        self.state.mkdir()
        for mode in (0o777, 0o770, 0o755):
            with self.subTest(mode=oct(mode)):
                self.state.chmod(mode)
                output = self.run_cli("init", self.root, code=1)
                self.assertIn("private permissions 0700", output)
                self.assertEqual(self.state.stat().st_mode & 0o777, mode)
                self.assertEqual(list(self.state.iterdir()), [])

    def test_valid_private_existing_state(self):
        self.state.mkdir(mode=0o700)
        self.init()
        self.run_cli("scan")
        self.run_cli("status")
        self.assertEqual(self.state.stat().st_uid, os.geteuid())
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)

    def test_state_permissions_rechecked(self):
        self.init()
        original = (self.state / "audit.log").read_bytes()
        self.state.chmod(0o755)
        try:
            for command in ("status", "scan", "report", "verify-log", "monitor"):
                with self.subTest(command=command):
                    self.assertIn("private permissions 0700", self.run_cli(command, code=1))
            self.assertEqual((self.state / "audit.log").read_bytes(), original)
        finally:
            self.state.chmod(0o700)

    @unittest.skipIf(os.geteuid() == Path("/").stat().st_uid, "Requires a directory owned by another user")
    def test_foreign_owned_state_rejected(self):
        # Read-only rejection must happen before trying to create a lock in /.
        self.assertIn("owned by the effective user", self.run_cli("status", state=Path("/"), code=1))

    def test_recursive_monitor_and_moves(self):
        self.init()
        with (self.base / "monitor.out").open("w+") as output:
            process = subprocess.Popen([BINARY, "monitor", "--state", str(self.state)], stdout=output, stderr=output)
            try:
                self.wait_event("MONITOR_START")
                self.run_cli("status")  # Monitor only locks state during appends.
                (self.root / "alpha.txt").write_text("changed by monitor test")
                self.wait_event("MODIFIED")
                (self.root / "nested").mkdir()
                (self.root / "nested" / "child").write_text("nested data")
                self.wait_event("NEW", "nested/child".encode().hex())
                (self.root / "nested" / "child").rename(self.root / "nested" / "renamed")
                self.wait_event("MOVE", "nested/renamed".encode().hex())
                (self.root / "nested").rename(self.root / "moved-directory")
                self.wait_event("MOVE", "moved-directory".encode().hex())
                (self.root / "moved-directory" / "renamed").write_text("still watched")
                self.wait_event("MODIFIED", "moved-directory/renamed".encode().hex())
                os.chmod(self.root / "alpha.txt", 0o400)
                self.wait_event("PERMISSION_CHANGE")
                (self.root / "alpha.txt").unlink()
                self.wait_event("DELETED", "alpha.txt".encode().hex())
                self.run_cli("monitor", "--duration", "1", code=1)
            finally:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                output.seek(0)
                captured = output.read()
            self.assertEqual(process.returncode, 0, captured)
        self.assertIn("MONITOR_STOP", self.run_cli("report"))

    def test_monitor_duration(self):
        self.init()
        self.assertIn("MONITOR_STOP", self.run_cli("monitor", "--duration", "1"))

    @unittest.skipIf(os.geteuid() == 0, "Permission denial requires a non-root user")
    def test_unreadable_file_fails_without_partial_state(self):
        os.chmod(self.root / "alpha.txt", 0)
        try:
            self.run_cli("init", self.root, code=1)
            self.assertFalse((self.state / "baseline.dat").exists())
        finally:
            os.chmod(self.root / "alpha.txt", 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
