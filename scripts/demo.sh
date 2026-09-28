#!/usr/bin/env bash
set -euo pipefail
audit_bin=$(realpath "${1:-./build/audit}")
demo_dir=$(mktemp -d /tmp/file-audit-demo.XXXXXX)
printf 'Demo files retained at: %s\n' "$demo_dir"
mkdir "$demo_dir/protected"
printf 'original\n' > "$demo_dir/protected/config.txt"
printf 'remove later\n' > "$demo_dir/protected/old.txt"
"$audit_bin" init "$demo_dir/protected" --state "$demo_dir/state"
"$audit_bin" scan --state "$demo_dir/state" --all
printf 'modified\n' > "$demo_dir/protected/config.txt"
printf 'new file\n' > "$demo_dir/protected/new.txt"
rm -- "$demo_dir/protected/old.txt"
scan_exit=0
"$audit_bin" scan --state "$demo_dir/state" || scan_exit=$?
if [[ "$scan_exit" -ne 2 ]]; then
    printf 'Expected a scan with differences (exit 2), got %s\n' "$scan_exit" >&2
    exit 1
fi
"$audit_bin" monitor --state "$demo_dir/state" --duration 4 &
monitor_pid=$!
trap 'kill "$monitor_pid" 2>/dev/null || true' EXIT
sleep 1
mkdir "$demo_dir/protected/nested"
printf 'observed live\n' > "$demo_dir/protected/nested/live.txt"
sleep 1
mv "$demo_dir/protected/nested/live.txt" "$demo_dir/protected/nested/renamed.txt"
wait "$monitor_pid"
trap - EXIT
"$audit_bin" report --state "$demo_dir/state"
"$audit_bin" verify-log --state "$demo_dir/state"
