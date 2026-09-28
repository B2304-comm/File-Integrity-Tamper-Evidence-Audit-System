# Configuration

Configuration is explicit through command-line arguments; no implicit config file is read.

- `--state PATH`: state location, default `.audit` in the current working directory.
- `--all`: include unchanged records in scan output.
- `--duration SECONDS`: positive monitor runtime, otherwise run until signaled.
- `--expect-head HASH`: exact trusted checkpoint for log verification.

Use a separate state directory for each protected root. Store checkpoints in a trusted location independent of that state directory.

State directories must be owned by the effective user with mode `0700`. New directories receive this mode; existing unsafe directories are rejected without automatic permission changes. Use a trusted Linux filesystem location and trusted parent directories, especially when invoking the tool from a Windows-mounted WSL folder. Validation happens at command startup.

Monitor state-lock acquisition waits and retries interruptions; other CLI commands can return a busy error. A monitor waiting to write a batch may exceed `--duration` until the lock holder releases it.
