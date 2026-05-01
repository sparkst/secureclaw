# SecureClaw State Storage

Authoritative reference for every persistent state artifact SecureClaw produces.
Owner: Claude (orchestration). Reviewed: Foundation phase.

## Artifact table

| Artifact | Location | Lifecycle | Atomicity | Notes |
|---|---|---|---|---|
| Fix log | `~/.secureclaw/fix-log.jsonl` (via `platformdirs`) | Append-only; rotated at 1 MB | append-only with `fsync` | Each line: `{ts, file_sha256_before, file_sha256_after, action}` |
| File backups | `<scan-root>/.secureclaw/backups/<rel-path>.<ts>.bak` | Per-file last 5; age cap 90d | atomic-rename via `O_EXCL` temp | chmod 0600 on POSIX; restrictive ACL on Windows |
| Federated results | `tests/results/<sha>/<machine>.jsonl` | Last 50 commits | per-job JSON | Aggregated by `sc-fed` skill |
| Allowlist (Mark-as-safe) | `<scan-root>/.secureclaw/allowlist.json` | Persists with project | atomic write | Keyed by `(file, line, pattern_id, content_sha)` |
| Reviewed state | `<scan-root>/.secureclaw/reviewed.json` | Persists with project | append-only | Mark-as-reviewed only; no future-scan effect |
| Scan ID | uuid4, in-memory | Memory-only during scan; written to results | n/a | New uuid per scan |
| Benchmark cache | `tests/corpus/benchmarks/<name>/` | Vendored, pinned to upstream commit | committed | `.upstream` lockfile holds SHA256 |
| Quality gates | `tests/quality_gates.json` | Versioned in repo | committed | CODEOWNERS-gated changes |
| Calibration weights | `secureclaw/core/calibration.py` | Re-fit on minor releases | committed | Deterministic exhaustive grid search |
| User config | `~/.secureclaw/config.json` (via `platformdirs`) | User-managed | atomic write via `/api/preferences` | Schema in `secureclaw/rules/config-schema.json` |
| GUI session token | In-memory only | 30-min idle TTL; rotate-on-scan-complete | n/a | Bearer header; never logged |
| Disabled rules | `~/.secureclaw/disabled-rules.yaml` | User-managed | atomic write | Per-machine rule muting |

## Cross-platform behavior

`platformdirs` provides correct paths per OS:

- macOS: `~/Library/Application Support/secureclaw/`
- Linux: `~/.config/secureclaw/` (XDG-compliant)
- Windows: `%APPDATA%\secureclaw\`

Backup files always live alongside scanned content under `<scan-root>/.secureclaw/`
(not user home), so they move with the project and respect the project's VCS.

## Atomicity guarantees

- **Atomic writes** use the temp-file + fsync + rename pattern:
  ```python
  with tempfile.NamedTemporaryFile("w", delete=False, dir=parent) as tmp:
      tmp.write(content)
      tmp.flush()
      os.fsync(tmp.fileno())
  os.rename(tmp.name, target)
  ```
- **Append with fsync** for log files:
  ```python
  with open(log, "a") as f:
      f.write(line + "\n")
      f.flush()
      os.fsync(f.fileno())
  ```

## Retention

- Fix log: rotates at 1 MB → `<file>.1`, deleted beyond `.1`.
- Backups: last 5 per file, age cap 90 days, total disk cap 100 MB. `secureclaw fix --prune-backups` enforces.
- Federated results: last 50 commits' worth; older purged by GitHub Actions cleanup job.
