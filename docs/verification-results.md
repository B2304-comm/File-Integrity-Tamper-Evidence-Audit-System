# Verification results

## Historical verification: 28 September 2026 (Python-era tests)

The historical run below verified the targeted rapid-rename, monitor-lock, and state-directory fixes. At that time it superseded the original nine-case verification. It used the former Python integration suite and scripted demonstration; these are not the current test system or demonstration. The [sanitized historical transcript](verification-build.txt) remains labeled as the September 27 pre-fix run.

### Historical environment and build

Ubuntu through WSL, normal user (not root), GCC 13.3.0, CMake 3.28.3, OpenSSL 3.0.13, and Python 3.12.3. Debug and Release were configured from scratch in separate Linux filesystem build directories outside the project. No warning suppression flags were added.

| Check | Result |
| --- | --- |
| Clean Debug configure/build | Passed; zero observed compiler/configuration warnings or errors |
| Clean Release configure/build | Passed; zero observed compiler/configuration warnings or errors |
| Debug CTest | 2/2 targets passed; unit executable and all 19 integration cases |
| Release CTest | 2/2 targets passed; unit executable and all 19 integration cases |
| Targeted regression-only run | 10/10 passed |
| Release demo | Exit 0; report and verification both validated 13 records |
| Git ignore-rule checks | 31/31 expected ignored/allowed path checks passed |
| Local documentation links | No broken links found |

All test cases passed with **0 failures and 0 skips**. That historical CTest configuration contained two targets; the 19 Python cases ran inside its integration target. The 10 targeted regressions are a subset of those 19 cases, not additional unique cases.

The existing unit and integration suite was run after each source fix: 13 integration cases after the rename change, 15 after contention handling, and 19 after ownership/permission validation. The original nine test methods were retained. No existing assertion was weakened to obtain a passing result.

Historical measured durations: Debug CTest 3.07 seconds, Release CTest 3.01 seconds, and the separate 10-case regression run 1.130 seconds. These are small-fixture verification timings, not performance guarantees.

### Historical regression behavior verified

- `a -> b -> c`, replacing an existing `b`: both move records use the correct carried-forward old hash; the unsampled intermediate new hash is `-`.
- `d -> e` followed immediately by `e/f -> e/g`: the child move uses `e`, preserves sampled hashes, and further writes remain monitored.
- Ordinary file and directory renames continue to work.
- A busy state lock does not terminate the monitor; the prepared event is written exactly once after release.
- SIGTERM during a blocked append preserves the prepared event, then writes `MONITOR_STOP` after lock release.
- Existing state modes 0777, 0770, and 0755 are rejected without permission changes. Private 0700 state owned by the effective user is accepted.
- Later commands recheck state permissions; foreign-owned state is rejected before lock creation.

The historical scripted demo covered unchanged files, content modification, file creation/deletion, a new nested directory, a monitored rename, reporting, and chain verification.

### Historical GitHub readiness

At that historical stage, source, headers, tests, demo script, configuration notes, CMake configuration, README, useful documentation, and the two `.gitkeep` placeholders were intended for version control. The historical transcript uses `<PROJECT_ROOT>` and `<BUILD_DIR>` placeholders rather than personal paths.

`.gitignore` excludes build output, Python caches, `.audit/` at any depth, and the runtime `baseline.dat`, `audit.log`, `lock`, `monitor.lock`, and atomic-write temporary basenames under custom state paths. Extra user-created files in a custom state directory still require review. Keeping state outside the repository is recommended.

No project Git repository, commits, GitHub repository, or remote changes were created during this work. Nothing was pushed. The earlier audit found the supplied GitHub repository empty; this verification does not claim that source has been published there.

## Final C++ conversion verification (previously completed)

The results below were verified in this working session before this documentation-only update. They are separate from the historical results above; no tests were rerun for this documentation update, and no new date or timing measurement is asserted.

The final test system uses C++17 `unit_tests` and `integration_tests`. The latter retains all 19 integration cases and launches the real `audit` executable. The current demonstration consists of manual Linux-terminal commands in the README. The former `tests/integration.py` and `scripts/demo.sh` have been deleted; their historical evidence remains above and in the unchanged transcript.

| Previously verified check | Result |
| --- | --- |
| Fresh Release CMake/CTest conversion build | Configure and build succeeded; CTest registered unit and integration executables |
| Final warning-cleanup Release build | 0 compiler warnings; 0 compiler errors |
| Unit tests | Passed |
| C++ integration cases | 19 passed; 0 failed; 0 skipped |
| CTest integration command | Invokes `integration_tests` with the compiled `audit` path; no Python invocation |

The warning-cleanup build used `/tmp/fia-warning-release-37a7px` with `-Wall -Wextra -Wpedantic -Wconversion -Wshadow`. This warning-clean result applies to that later build, after explicit handling of the failed-exec diagnostic `write()` return value. Application source/header files were unchanged by the conversion. No custom Linux device driver was implemented.

Existing generated files in the old repository-local `build/` and `build-ubuntu-test/` directories still contain stale Python test commands. They are not the verified fresh build or the current CMake configuration; reconfigure an old build directory before using its CTest registration.

## Remaining limits and manual attention

Use a trusted Linux filesystem state location owned by the effective user with mode `0700`. If an existing directory is rejected, inspect its ownership and purpose before correcting its permissions; the program intentionally does not do that automatically. Windows-mounted paths may not provide the required Linux permissions. Parent-directory trust remains the operator's responsibility.

The monitor preserves batches already prepared for append, but does not drain every pending kernel event or perform a final scan on shutdown. A permanently held lock can delay shutdown indefinitely; queue overflow remains possible while waiting. Forced termination and real I/O errors are not recovered automatically.

Rename hashes are sampled snapshot values rather than measurements at every intermediate operation. Incomplete pairs, queue overflow, short-lived files, and concurrent tree changes still prevent a complete forensic history. Whole-tree scans are not atomic.

Complete trailing-record removal still needs a separately trusted checkpoint. A partial final record fails verification directly. An attacker able to rewrite all local evidence can recompute the unkeyed chain.

Queue-overflow injection, power loss, mount changes, adversarial traversal races, large-tree performance, and sanitizer execution were not part of the historical run above or the subsequent C++ conversion verification. No results are claimed for them.
