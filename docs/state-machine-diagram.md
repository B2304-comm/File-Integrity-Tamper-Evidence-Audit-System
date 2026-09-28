# State-machine diagram

These states describe existing CLI behavior and stored baseline availability. They are conceptual lifecycle states, not a new persisted state field or a background service.

```mermaid
stateDiagram-v2
    state "Uninitialized" as Uninitialized
    state "Initialized" as Initialized
    state "Scanning" as Scanning
    state "Monitoring" as Monitoring
    state "Error" as Error
    state "Stopped" as Stopped

    [*] --> Uninitialized: No usable baseline
    Uninitialized --> Scanning: init / validate root and private state
    Uninitialized --> Error: Invalid arguments or state location
    Scanning --> Initialized: init / publish baseline and INIT
    Initialized --> Scanning: scan / verify saved state
    Scanning --> Initialized: scan complete / exit 0 clean or 2 changed
    Scanning --> Error: Read, validation, or persistence failure
    Initialized --> Monitoring: monitor / lock, install watches, initial scan
    Initialized --> Error: Validation or startup failure
    Initialized --> Initialized: status, report, or verify-log succeeds
    Monitoring --> Monitoring: Events or periodic scan / compare and append
    Monitoring --> Monitoring: State busy / retain batch and wait
    Monitoring --> Monitoring: Recoverable scan failure / record SCAN_ERROR
    Monitoring --> Error: Fatal root, verification, locking, or I/O failure
    Monitoring --> Stopped: Signal or duration / finish pending append and log stop
    Error --> Stopped: Fatal command error / exit 1
    Stopped --> Initialized: Later command finds valid saved state
    Stopped --> Uninitialized: No usable saved state
```

`init` and `scan` use the same scanner but different completion actions. A changed scan exits with code 2; it is not an error state. Successful short commands exit while leaving persistent state initialized. `help` only prints usage and does not require initialized state.

The monitor's initial scan compares against the baseline. Later scans compare against the last successful snapshot. A recoverable scanning error is logged inside monitoring; fatal errors propagate to the CLI and exit with code 1. A failed initialization can leave incomplete files and requires inspection before using a new state directory.

Waiting for the state lock remains part of monitoring, not a new state. Pending event batches are kept until the lock is acquired, including after SIGTERM/SIGINT. An indefinitely held lock can therefore delay shutdown indefinitely. A normal stop does not perform a final scan or drain every queued event; `MONITOR_STOP` records process shutdown, not complete coverage through that instant.
