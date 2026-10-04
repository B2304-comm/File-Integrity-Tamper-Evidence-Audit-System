# Testing

Run on Linux as a normal user, using a local Linux filesystem for test fixtures:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

CTest runs two C++17 executables:

- `unit`: runs `unit_tests`, which checks standard SHA-256 vectors (empty input, `abc`, one million `a` bytes), binary encoding roundtrips, invalid encoding rejection, and integrity difference classification.
- `integration`: runs `integration_tests` with the compiled `audit` executable path. Its 19 cases in isolated temporary fixtures exercise the real executable. The original 9 cases cover streaming binary hashes, unusual filenames, baselines retained unchanged across scans, content/metadata changes, symlink and FIFO exclusion, unreadable files, state/root validation, concurrent state locking, baseline tampering, edited/reordered/truncated logs, checkpoint checks, recursive monitoring, rename handling, permission events, monitor exclusivity, timed completion, and signal shutdown.

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

A test-local OpenSSL EVP helper calculates expected SHA-256 values independently of the application hash helper. Tests do not require root or edit user files. Run as a normal Linux user: the unreadable-file test is skipped for root, and the foreign-owner case is skipped when the user owns `/`. Monitor tests wait for recorded events with bounded deadlines. Rapid-rename tests briefly suspend only their own monitor subprocess with SIGSTOP to place related operations in the same batch. Contention tests inspect that subprocess's Linux `/proc/PID/wchan` to synchronize with blocked lock acquisition. Temporary fixtures are removed by the test harness.

To run the complete integration suite directly:

```bash
./build/integration_tests ./build/audit
```

The harness accepts the audit executable path and runs all 19 cases; it does not provide per-case selection. It reports individual PASS/FAIL/SKIP results and returns nonzero if any case fails. Checks use explicit exceptions rather than Release-disabled assertions. `fork`/`execv` launch the real CLI without shell scripts, pipes capture stdout/stderr with `poll`, and `waitpid` checks exit status. CLI calls have a 15-second deadline; event waits use 8 seconds and state-lock synchronization uses 5 seconds. RAII cleans up processes, descriptors, locks, temporary permission changes, and `mkdtemp` fixtures.

| C++ test function | Coverage |
| --- | --- |
| `test_scan_and_metadata` | Unchanged/content/deletion/new/permission/mtime events, unusual filename escaping, report digest, and original baseline retention. |
| `test_symlinks_special_files_and_binary_hash` | External/loop symlinks and FIFO exclusion; multi-buffer binary SHA-256. |
| `test_log_tampering_and_checkpoint` | Edited/reordered records, incomplete final record, valid shortened prefix, checkpoint mismatch, and refusal to append to a broken chain. |
| `test_baseline_corruption_and_binding` | Corrupt checksum and altered baseline with recomputed checksum rejected through INIT binding. |
| `test_validation_and_locking` | Nested state, reinitialization, wrong root/options, lock contention, and missing log. |
| `test_empty_tree` | Zero-file initialization and scan. |
| `test_rapid_file_rename_chain` | Queued replacement rename chain, ordered MOVE records, sampled hashes, and replacement detail. |
| `test_rapid_directory_then_child_rename` | Queued directory/child rename, updated source paths, hashes, and continued watches without false NEW/DELETED. |
| `test_single_file_rename_hashes` | One MOVE with exact path, source detail, and old/new hashes. |
| `test_single_directory_rename_keeps_watch` | One directory MOVE, continued descendant monitoring, and no false NEW/DELETED. |
| `test_monitor_waits_for_state_lock` | Pending modification retained while blocked and appended exactly once after release. |
| `test_monitor_preserves_pending_append_on_signal` | SIGTERM during blocked append preserves the event before MONITOR_STOP. |
| `test_unsafe_existing_state_permissions` | Modes 0777/0770/0755 rejected without changing permissions or creating state files. |
| `test_valid_private_existing_state` | Existing effective-user-owned 0700 state accepted. |
| `test_state_permissions_rechecked` | Five later commands reject unsafe permissions without changing the log. |
| `test_foreign_owned_state_rejected` | Foreign ownership rejected before lock creation. |
| `test_recursive_monitor_and_moves` | Concurrent status, nested discovery, file/directory moves, continued watches, permissions, deletion, monitor exclusivity, and signal shutdown. |
| `test_monitor_duration` | Timed completion with MONITOR_STOP. |
| `test_unreadable_file_fails_without_partial_state` | Unreadable input rejected without baseline publication. |

Baseline retention is an application policy, not write protection for files. See [verification results](verification-results.md) for previously recorded runs; this documentation update does not constitute a new test run.

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
