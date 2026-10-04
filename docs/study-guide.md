# Code walkthrough and presentation preparation

Use this guide with the source open. For each stop, explain the behavior aloud and point to the relevant function before reading the next stop. This is a study aid for the AI-assisted implementation, not evidence of independent authorship.

## 1. README: understand the contract

Start with [README.md](../README.md). Explain the seven commands, why state is separate from protected files, and why a changed scan exits with code `2`. A nonzero result is not always an operational failure. `status` reports saved information; it does not perform a fresh scan.

Predict the output before running the demo. A second scan of the same changed file still reports the difference because the original baseline remains unchanged.

## 2. Architecture and shared data

Read [architecture.md](architecture.md), then [Types.hpp](../include/Types.hpp). `FileRecord` holds one file's digest and metadata. `Snapshot` maps relative paths to records. `Baseline` adds the absolute protected root. `Event` carries a classification and associated hashes. `Verification` holds the number of valid log records and final chain hash.

Trace this data flow on paper: directory -> snapshot -> comparison -> events -> chained records. The monitor uses the same scanner and comparison code as the scan command.

## 3. main.cpp: follow one command

Open [main.cpp](../src/main.cpp). Find argument parsing and the branch for `init`. Follow root validation, snapshot creation, baseline persistence, log creation, and `INIT` append in that order. Then trace `scan`: load and validate state, read the tree, compare, append events, and return `0` or `2`.

Find the check comparing the baseline-file hash with the first log record. Explain why checking a file's self-checksum alone cannot detect a deliberate rewrite that also updates that checksum. `verify-log` verifies the chain itself; it does not scan protected files or independently validate the baseline.

## 4. HashManager.cpp: understand SHA-256

Open [HashManager.cpp](../src/HashManager.cpp). SHA-256 produces a 256-bit digest, displayed as 64 hexadecimal characters. The same bytes produce the same digest. Hashing does not encrypt the file and does not reveal whether its contents are good or authorized.

`Digest` owns an OpenSSL context. Initialization selects SHA-256, `update` supplies bytes, and `finish` produces the digest. `descriptor` repeatedly reads up to 65,536 bytes and hashes the bytes actually returned. It retries reads interrupted by a signal. This follows OpenSSL's [streaming digest interface](https://docs.openssl.org/3.0/man3/EVP_DigestInit/).

Explain why a 200 KiB file does not need a 200 KiB content buffer here. Also explain why that does not make the whole program constant-memory: snapshots and log parsing grow with their inputs.

## 5. FileScanner.cpp and Support.hpp: safe resource handling

Open [FileScanner.cpp](../src/FileScanner.cpp) and [Support.hpp](../include/Support.hpp). `scan` opens the protected root. `walk` enumerates entries, recursively opens directories, and handles regular files. Symlinks and special files are skipped.

`openat` works relative to an already open parent descriptor. `fstat` examines the open file; `fstatat` checks the named entry. The `stable` comparison checks identity and metadata before and after hashing to catch common concurrent changes. A changing or unreadable file raises an exception instead of producing a partly valid snapshot.

Find `Fd::~Fd` and the custom directory-stream deleter. Explain RAII: when an owning C++ object leaves scope, its destructor releases the resource, including during exception unwinding. Explain why copying the owner is disabled.

## 6. ConfigManager.cpp: create and trust a baseline

Open [ConfigManager.cpp](../src/ConfigManager.cpp). `validateRoot` canonicalizes paths and rejects overlapping protected/state trees. `saveBaseline` serializes sorted records and adds a checksum. `loadBaseline` checks the checksum and validates paths, modes, timestamps, hashes, and duplicate entries.

`prepareState` requires effective-user ownership and mode `0700` before opening state files. New directories receive private permissions; existing unsafe directories are rejected without changing their permissions. Explain why file mode `0600` alone is insufficient when an untrusted user can replace entries in the containing directory.

`atomicWrite` writes a temporary file, synchronizes it, renames it into place, and synchronizes the directory. This publishes a complete individual file; initialization of the baseline and log together is not one atomic transaction.

`StateLock` is nonblocking by default, so competing short commands receive a busy error. The monitor requests blocking acquisition for its startup read and appends, retrying interruptions and keeping a pending batch until it can be saved. The separate single-monitor lock remains nonblocking. A stop signal does not abandon a batch waiting for the lock; shutdown waits for release, but still does not drain all kernel events or perform a final scan. Hex encoding preserves filename bytes without letting tabs/newlines become record separators; it provides no secrecy.

## 7. IntegrityChecker.cpp: predict the classification

Open [IntegrityChecker.cpp](../src/IntegrityChecker.cpp) and work through these cases:

| Before / after | Event |
| --- | --- |
| Path absent before, present now | `NEW` |
| Path present before, absent now | `DELETED` |
| Hash or size changes | `MODIFIED` |
| Permission bits change | `PERMISSION_CHANGE` |
| Only modification time changes | `METADATA_CHANGE` |
| Compared fields match | `UNCHANGED`, displayed only with `--all` |

A content change and a permission change can produce two events for one file. The reported change count is an event count, not necessarily a unique-file count. Modification-time differences do not add a separate metadata event when a content or permission event is already emitted.

## 8. AuditLogger.cpp: verify a chain by hand

Open [AuditLogger.cpp](../src/AuditLogger.cpp). Every serialized record has ten fields. Its current hash covers the exact first nine fields, including the previous hash and tab separators. The first record starts with a previous hash of 64 zeroes.

```text
record 1: previous = zeroes     -> H1 = SHA256(serialized fields 1..9)
record 2: previous = H1         -> H2 = SHA256(serialized fields 1..9)
record 3: previous = H2         -> H3 = SHA256(serialized fields 1..9)
```

`verify` checks the sequence, previous-hash link, field format, and recomputed current hash. `append` verifies before writing so it refuses to extend a broken chain. `report` displays records only after verification succeeds.

If record 3 is removed completely, records 1 and 2 remain valid. Their bytes never referred to a future record. A trusted copy of H3 proves the current head H2 differs from the expected state. A partial final line is a different case: this implementation rejects it directly.

## 9. FileMonitor.cpp: events trigger content checks

Open [FileMonitor.cpp](../src/FileMonitor.cpp). Find watch registration, the `poll` loop, event parsing, rename-cookie matching, snapshot comparison, and signal handling. No custom Linux device driver is implemented; inotify is a kernel notification API called from user space. Inotify reports filesystem notifications; it does not compute content hashes. This program uses notifications to trigger scanning and also reconciles periodically.

The monitor adds watches for subdirectories because inotify directory watches are not recursive. It associates `IN_MOVED_FROM` and `IN_MOVED_TO` by cookie within the processed batch. Overflow triggers a warning record and reconciliation. See the [Linux API reference](https://man7.org/linux/man-pages/man7/inotify.7.html).

Trace `a -> b -> c`: completed pairs are processed in event order and the snapshot is relocated after each move. Both old hashes come from the same last-observed source contents. The unsampled intermediate destination gets `-` for its new hash. For `d -> e` followed by `e/f -> e/g`, watch paths change immediately on the directory pair so the child event uses `e`. These are snapshot-based hashes, not proofs of content at each instantaneous operation. Unpaired or uncertain paths are left to reconciliation rather than guessed.

Keeping the original baseline means keeping a comparison reference, not preventing external file writes.

The initial snapshot is compared against the original baseline. Later snapshots are compared against the preceding successful snapshot. That distinction prevents every notification from repeatedly logging all old unresolved deviations. Signals set a flag; ordinary code writes the stop event. Do not describe it as lossless forensic recording or a hard real-time system.

## 10. CMake, tests, and demo

Open [CMakeLists.txt](../CMakeLists.txt). CMake configures a build; the compiler compiles C++ and the linker resolves object files and OpenSSL symbols. `audit_core` contains reusable modules, `audit` adds the CLI, and `unit_tests` links the core. `integration_tests` links OpenSSL Crypto and depends on the built `audit` executable. CTest runs `unit_tests` and `integration_tests` as two test targets; the integration command receives the compiled `audit` path.

Read [unit_tests.cpp](../tests/unit_tests.cpp), then [integration_tests.cpp](../tests/integration_tests.cpp). Unit tests check smaller functions against known expectations. Integration tests launch the actual CLI with temporary directories and verify outcomes. Nineteen C++ test functions (9 original and 10 regressions) run inside the integration target; CTest still has only two targets. Follow `Fixture` for temporary files, `Child` for fork/exec and waitpid, `run` for stdout/stderr capture and timeouts, and `require` for checks that remain active in Release builds. RAII closes descriptors, reaps children, and removes temporary fixtures. The test-local `sha256` helper uses OpenSSL EVP rather than the application hash helper.

Trace `test_log_tampering_and_checkpoint` and `test_recursive_monitor_and_moves` in detail. Point out an untested area, such as deterministic event-queue overflow or power loss. Use the manual Linux-terminal demonstration in the [README](../README.md#try-it). Explain why a changed scan returns exit code `2`; it is a successful comparison with differences. Keep the temporary path for a second terminal, start monitoring, then create a nested file, rename it, and inspect the report after stopping.

## Interview practice

Answer without reading, then check these key points:

1. **Why SHA-256 rather than size alone?** Different contents can have the same size. Hashes compare content, subject to the digest's cryptographic assumptions.
2. **Does a matching hash prove the file is safe?** No. It only matches the reference bytes; the initial reference must be trusted.
3. **Why keep state outside the protected tree?** Log/baseline writes would otherwise change the monitored input.
4. **Why scan if inotify already reports changes?** Notifications identify activity; scanning establishes content and metadata differences and reconciles missed notifications.
5. **Why can a valid log be incomplete?** Deleting its tail leaves an internally valid prefix.
6. **Can an attacker rebuild the chain?** Yes, if they can replace local evidence. A separately trusted checkpoint or authentication mechanism is needed to resist that.
7. **What happens if hashing fails halfway through?** The scan throws; it does not publish a partial baseline or log a successful scan.
8. **What does `flock` protect?** Cooperating state access, not arbitrary external writers or privileged attackers.
9. **Where does user mode meet kernel mode?** At system calls used for files, notifications, locks, and persistence. OpenSSL hashing runs in user space.
10. **What changes between `scan` and `monitor` comparison?** Scan uses the original baseline; monitor uses successive observations after startup.
11. **Which C++ ownership concept is central?** RAII; destructors release file descriptors, directory streams, and digest contexts.
12. **What do passing tests establish?** The tested cases work in the verified environment, not proof against all faults or attacks.

## Suggested seven-minute explanation

| Time | Show and explain |
| --- | --- |
| 0:00–0:45 | The file-change problem and the tool's detection scope. |
| 0:45–1:30 | Architecture and module responsibilities. |
| 1:30–3:30 | Run the manual terminal demo; explain baseline, changed scan, nested monitoring, and rename. |
| 3:30–4:30 | Report fields, hash chaining, and external-checkpoint limitation. |
| 4:30–5:30 | Linux calls, RAII, CPU/RAM/storage interaction. |
| 5:30–6:30 | Test results and one important coverage gap. |
| 6:30–7:00 | Limitations and future scope. |

Practice identifying the relevant source file for each claim. Describe actual assistance and work accurately rather than presenting a generated implementation as independent authorship.
