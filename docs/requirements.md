# Requirements and implementation map

| Requirement | Implementation / acceptance check |
| --- | --- |
| Linux C++ system programming | C++17, CMake, Linux-only build; descriptors, openat, read, fstat, inotify, poll, flock, fsync |
| Recursive file enumeration | FileScanner; regular files beneath a canonical protected root |
| SHA-256 | OpenSSL EVP; standard known-answer vectors and a test-local EVP expected-digest comparison |
| Persistent baseline | ConfigManager; path, hash, size, mode, mtime; checksum and INIT binding |
| Trusted state | Effective-user ownership and private mode 0700 checked before opening state files |
| Content comparison | IntegrityChecker; unchanged, modified, new, deleted |
| Metadata changes | Permission bits and modification time |
| Best-effort monitoring | Recursive inotify watches, move pairing, new directory discovery, periodic reconciliation |
| Contention handling | Monitor waits with its pending batch retained; short commands remain nonblocking |
| Audit records | UTC timestamps, event type, paths, hashes, and details |
| Tamper evidence | Sequence checks and previous-record hash chain; optional external-head check |
| CLI | init, scan, status, monitor, report, verify-log, help |
| Testing | CTest runs C++ unit_tests and integration_tests; 19 Linux black-box integration cases |
| Architecture documentation | User/kernel boundary, CPU, RAM, storage, caches, I/O, events |
| Lifecycle documentation | State-machine diagram of initialization, scanning, monitoring, errors, and stopping |

## Acceptance scenario

1. Initialize a directory containing a file and confirm a clean scan.
2. Change its contents and observe `MODIFIED` with old and new hashes.
3. Add and remove files and observe `NEW` and `DELETED`.
4. Change file permissions and observe `PERMISSION_CHANGE`.
5. Monitor a directory, add a nested directory, and change a nested file.
6. Rename a file and a directory; inspect corresponding move events.
7. Display the verified audit report.
8. Save the log head separately, alter a log record, and observe failed verification.
9. Remove the last record and observe checkpoint mismatch even if the remaining prefix is internally valid.

The tool records evidence only. It does not prevent writes, restore files, authenticate users, send alerts, or automatically approve a replacement baseline.

Inotify is a Linux filesystem notification API, not a custom device driver. No custom Linux device driver is implemented. The application retains the original baseline during scans; this does not prevent external file modifications. Hash chaining is tamper-evident, not tamper-proof: there are no digital signatures, someone able to rewrite all local evidence may recompute the chain, and detecting removal of complete trailing records requires a trusted checkpoint.
