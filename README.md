# File Integrity & Tamper-Evidence Audit System

A C++17 command-line application for Linux. It saves SHA-256 baselines, detects changes to regular files, monitors directories recursively through inotify, and keeps a verifiable hash chain of audit events.

## Build

On Ubuntu, including Ubuntu in WSL:

```bash
sudo apt-get update
sudo apt-get install -y g++ cmake libssl-dev python3
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/audit help
```

From PowerShell in this project directory, use `wsl -d Ubuntu -- ./build/audit help` to run the built Linux executable. A native Windows build is not supported. Under WSL, put both protected files and state in the Linux filesystem, for example under your Linux home directory, and modify protected files from Linux processes. Windows-mounted locations may not enforce the private Linux permissions required for state; use an explicit Linux `--state` path when running from this Windows project folder.

## Try it

Run these commands from the project directory in a Linux/WSL terminal. The demo uses a unique temporary directory so it does not overwrite existing files.

```bash
demo_dir=$(mktemp -d /tmp/file-audit-demo.XXXXXX)
mkdir "$demo_dir/protected"
printf 'original\n' > "$demo_dir/protected/config.txt"

./build/audit init "$demo_dir/protected" --state "$demo_dir/state"
./build/audit scan --state "$demo_dir/state" --all

printf 'modified\n' > "$demo_dir/protected/config.txt"
./build/audit scan --state "$demo_dir/state"
# Exit code 2 means differences were found.

./build/audit report --state "$demo_dir/state"
./build/audit verify-log --state "$demo_dir/state"
./build/audit monitor --state "$demo_dir/state" --duration 30
# While monitoring, edit files from a second Linux terminal.
```

Run `bash scripts/demo.sh ./build/audit` for an automated demonstration of modification, creation, deletion, monitoring, reporting, and log verification. It prints the retained demo directory for inspection.

## Commands

| Command | Behavior |
| --- | --- |
| `init <directory>` | Create a baseline and the initial audit record. Refuses to overwrite existing state. |
| `scan [directory]` | Compare with the original baseline, log differences and a scan summary. |
| `scan --all` | Also display unchanged files and their hashes. |
| `status` | Display stored root, baseline file count, audit record count, and log head. Does not scan. |
| `monitor [directory]` | Watch recursively until Ctrl+C or SIGTERM. |
| `monitor --duration 30` | Watch for 30 seconds. |
| `report` | Verify the entire chain before displaying decoded events. |
| `verify-log` | Verify record sequence numbers, previous hashes, and record hashes. |
| `verify-log --expect-head <hash>` | Also compare with an exact externally saved checkpoint. |
| `help` | Show usage. |

All commands accept `--state PATH`; the default is `.audit` relative to the current working directory. Always use the same state path for a protected tree. State and protected trees must be separate and must not contain each other. Paths with spaces should be quoted. An optional directory on `scan` or `monitor` must resolve to the initialized root.

The state directory must be owned by the effective user and have mode `0700` (owner read/write/execute only). New state directories receive this mode. Existing directories with another owner or different access permissions are rejected before state files are opened; their permissions are not changed automatically. Existing valid private directories continue to work. Choose a location whose parent directories you trust. This check does not protect against a privileged attacker or someone able to replace a parent directory, and it is performed at command startup rather than continuously.

Exit codes are **0** for success or a clean scan, **1** for invalid input, operational failure, or failed verification, and **2** for a completed scan with differences. A scan may emit both a content event and a permission event for the same file.

The baseline remains unchanged across scans. To intentionally establish a new baseline, initialize a new state directory and retain the old state as history. This application does not automatically accept changed files as trusted.

## What it records

- `NEW`, `MODIFIED`, `DELETED`, `PERMISSION_CHANGE`, and `METADATA_CHANGE` (mtime only).
- `MOVE` when a monitor batch contains a matching inotify rename cookie pair, including directory moves. Completed pairs are handled in event order, and directory watch paths are updated before later child events. Unpaired or uncertain moves fall back to snapshot differences when those differences are observable.
- `INIT`, `SCAN`, `MONITOR_START`, `MONITOR_STOP`, `QUEUE_OVERFLOW`, and `SCAN_ERROR` operational events.

Each event includes its sequence number, UTC timestamp, type, path, old/new hashes where available, details, previous record hash, and current record hash. Paths and details are hex encoded on disk, so tabs and newlines in filenames cannot inject extra records. CLI output escapes control characters.

Move hashes describe sampled file contents, not measurements at the exact instant of a rename. The old hash comes from the last successful snapshot, carried through earlier moves in the batch. The new hash comes from the final snapshot only if later moves do not affect that destination; otherwise it is `-`. Thus `a -> b -> c` retains the same last-observed old hash for both moves, but an unsampled intermediate destination has no invented new hash. A directory rename followed by a child rename uses the updated directory path. Overflow and incomplete pairs cannot provide a complete operation history.

The monitor initially compares against the baseline, then compares each snapshot with the preceding successful snapshot. It batches notifications and attempts periodic reconciliation at approximately two-second intervals; scans and lock waits can extend that interval. `scan` always compares against the baseline, so repeated scans repeat unresolved differences. Only one monitor may use a state directory. The monitor waits for cooperating state-lock holders at startup and during appends, retaining an already prepared event batch until the lock becomes available. Other commands still return a “busy” error when their nonblocking acquisition fails. Kernel events can accumulate or overflow while the monitor waits.

On SIGINT, SIGTERM, or a duration limit, a batch already waiting to be appended is preserved and written before `MONITOR_STOP`. Lock acquisition interrupted by a signal is retried, so shutdown can wait beyond the requested duration until the other command releases its lock. The monitor does not drain all remaining kernel notifications or perform a final scan. An orderly stop therefore does not prove that every pending filesystem change was recorded. Forced termination or a real I/O error can still prevent an append or stop record.

## Integrity and scope

The system is **tamper-evident, not tamper-proof**. A chain detects changed, reordered, or missing internal records unless someone recomputes the chain. Detecting removal of complete trailing audit records requires a separately trusted checkpoint: a valid prefix still verifies after suffix removal, even if only the log header remains. A partial final record is rejected directly. Save the reported log head in a separate trusted location and use `--expect-head` to detect changes relative to that checkpoint. The checkpoint must cover the history being protected. This option expects the exact head: legitimate later appends also change it. No checkpoint is automatically stored outside the local state directory.

Baseline files have a checksum and are bound to the initial log record. An attacker able to replace both baseline and log can rewrite all local evidence. There is no signature, remote service, secret key, or hardware trust anchor. File permissions help with accidental access; a privileged attacker can bypass them.

Only regular files are baselined. Symlinks are not followed, and sockets, FIFOs, device nodes, directory metadata, ownership, ACLs, and extended attributes are outside scope. Permission bits, file size, modification time, and content hashes are recorded for regular files. An unreadable or concurrently changing file fails a scan instead of silently producing a partial baseline. `openat`, `O_NOFOLLOW`, and before/after metadata checks reduce traversal races; a directory tree scan is not an atomic filesystem snapshot.

Inotify is a notification mechanism, not a complete forensic record: changes may be coalesced, short-lived files may disappear between snapshots, and mount/network filesystem behavior can differ. Overflow is logged and triggers reconciliation; lost event history cannot be reconstructed. Scanning and hashing are linear in total file contents; baseline and log parsing use memory proportional to their size. The implementation favors clarity over high-volume performance.

State consists of `baseline.dat`, `audit.log`, `lock`, and `monitor.lock`. Baselines are published using temporary files, `fsync`, and atomic rename. Log appends are synchronized to disk. A crash during initialization may leave incomplete state; use a new state directory after inspecting it. A crash during an append may leave a partial record; verification fails and the tool refuses further appends. It never silently repairs or discards evidence.

## Project layout

```text
include/       Module interfaces and shared data types
src/           C++ implementations and CLI
tests/         SHA-256/unit tests and Linux integration tests
scripts/       Automated demo
config/        Configuration notes
baseline/      Reserved placeholder; actual data goes under --state
logs/          Reserved placeholder; actual data goes under --state
docs/          Requirements, architecture, diagrams, and testing notes
```

See [architecture](docs/architecture.md), [requirements](docs/requirements.md), [class diagram](docs/class-diagram.md), [sequence diagrams](docs/sequence-diagram.md), [state-machine diagram](docs/state-machine-diagram.md), and [testing](docs/testing.md).

For GitHub, commit source, headers, tests, scripts, CMake configuration, documentation, and the two `.gitkeep` placeholders. Build output, Python caches, `.audit/`, and runtime baseline/log/lock basenames (including under custom state paths) are ignored. Keep custom state directories outside the repository when possible; review any extra files in them before staging. The sanitized historical verification transcript in `docs/verification-build.txt` is documentation, not a runtime log.

For review and presentation preparation, see the [16-section capstone report](docs/capstone-report.md), [file-by-file study guide and interview practice](docs/study-guide.md), and [recorded verification results](docs/verification-results.md).
