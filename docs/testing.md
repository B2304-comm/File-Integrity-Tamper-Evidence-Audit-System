# Testing

Run on Linux as a normal user, using a local Linux filesystem for test fixtures:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

CTest runs two targets:

- `unit`: standard SHA-256 vectors (empty input, `abc`, one million `a` bytes), binary encoding roundtrips, invalid encoding rejection, and integrity difference classification.
- `integration`: 19 cases in isolated temporary fixtures exercise the real executable. The original 9 cases cover streaming binary hashes, unusual filenames, immutable baselines, content/metadata changes, symlink and FIFO exclusion, unreadable files, state/root validation, concurrent state locking, baseline tampering, edited/reordered/truncated logs, checkpoint checks, recursive monitoring, rename handling, permission events, monitor exclusivity, timed completion, and signal shutdown.

The 10 added regression cases check:

1. `a -> b -> c`, including replacement of an existing `b`, with correct old hashes and an unavailable intermediate new hash.
2. `d -> e` followed immediately by `e/f -> e/g`, without obsolete child paths.
3. Normal single-file rename hashes.
4. Normal directory rename followed by another change beneath the moved directory.
5. Monitor state-lock contention with the event retained and appended exactly once.
6. SIGTERM during a blocked append, followed by event persistence and `MONITOR_STOP` after lock release.
7. Rejection of existing state modes 0777, 0770, and 0755 without altering their permissions.
8. Acceptance of an existing private 0700 state directory.
9. Permission revalidation on later state-using commands without changing the log.
10. Rejection of a foreign-owned directory before lock creation.

Python's `hashlib` provides an independent digest comparison. Tests do not require root or edit user files. Run as a normal Linux user: the unreadable-file test is skipped for root, and the foreign-owner case is skipped when the user owns `/`. Monitor tests wait for recorded events with bounded deadlines. Rapid-rename tests briefly suspend only their own monitor subprocess with SIGSTOP to place related operations in the same batch. Contention tests inspect that subprocess's Linux `/proc/PID/wchan` to synchronize with blocked lock acquisition. Temporary fixtures are removed by the test harness.

To run just the new regressions after building, pass these unittest method names to `tests/integration.py`, for example:

```bash
python3 tests/integration.py ./build/audit \
  AuditTests.test_rapid_file_rename_chain \
  AuditTests.test_rapid_directory_then_child_rename \
  AuditTests.test_single_file_rename_hashes \
  AuditTests.test_single_directory_rename_keeps_watch \
  AuditTests.test_monitor_waits_for_state_lock \
  AuditTests.test_monitor_preserves_pending_append_on_signal \
  AuditTests.test_unsafe_existing_state_permissions \
  AuditTests.test_valid_private_existing_state \
  AuditTests.test_state_permissions_rechecked \
  AuditTests.test_foreign_owned_state_rejected
```

## Additional manual checks

For large trees, observe CPU and I/O during the two-second reconciliation cycle. With a separate disposable fixture, generate enough events to overflow the kernel queue and inspect `QUEUE_OVERFLOW` and subsequent reconciliation. Queue overflow, abrupt power loss, mount changes, and adversarial filesystem races are not deterministically exercised by the automated suite.

To inspect tamper detection manually, copy a state directory before editing its log. Alter one event byte and run `verify-log`; it must fail. Delete the last complete record and compare the current head with a previously saved checkpoint using `--expect-head`. Without a trusted checkpoint, a valid shortened prefix is expected to verify.

An optional sanitizer build can be created with:

```bash
cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-sanitize -j
ctest --test-dir build-sanitize --output-on-failure
```
