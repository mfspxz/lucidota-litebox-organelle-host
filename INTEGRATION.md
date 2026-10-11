# LiteBox Organelle Host — Exocortex Integration

**Status:** architecture defined, host built, wiring is the next lane.
**Host binary:** `~/workspace/litebox-organelle-host/target/debug/litebox-organelle-host`

## The execution path

```
GOVERNOR allocates task → EXCHANGE routes to lane → ORGANELLE HOST runs it
    │
    ▼
┌─────────────────────────────────────────────────┐
│ litebox-organelle-host <bundle.tar> <manifest>  │
│                                                 │
│ OUTER (kernel): user/mount/PID/net namespaces,  │
│   seccomp deny-by-default, zero caps, rlimits,  │
│   watchdog                                      │
│ INNER (LiteBox): syscall rewriting, virtual FS  │
│   (no telemetry API — fields null/unavailable) │
│                                                 │
│ EMITS: receipt.json (PL-style)                  │
└─────────────────────────────────────────────────┘
    │
    ▼
PROOF LEDGER ← receipt (claims, syscalls, files, artifact hash)
```

## Interface contract

**Input:**
- `bundle.tar` — the organelle: code + manifest. Hashed (tar_hash in receipt).
- `manifest.json` — `{organelle_id, entrypoint, args, policy_hash, resource_limits}`
- `policy.json` — allowlist (delivered read-only via the guest tar), syscall policy, timeout.

**Output (`receipt.json`):**
- `outer_sandbox` — namespaces, seccomp, caps, rlimits actually applied
- `syscalls_allowed` / `syscalls_denied` — null (shim exposes no telemetry API;
  receipt marks `telemetry_status: unavailable`, never zero-as-unknown)
- `files_read` / `files_written`
- `exit_status`, `resource_usage` (wait4 rusage)
- `artifact_hash` — sha256 of the retained stdout prefix (16MiB budget;
  truncation recorded honestly with byte counts when the guest floods)
- `policy_hash`, `tar_hash`
- `caveats` — honest unknowns

## Lane mapping (exchange)

The host is a **lane type** in the exchange registry, not a special case:
- `lane-kind: organelle-host`, `measured caps`: from cooperative runs
- Governor routes sandboxed-execution tasks here when policy requires it
- Non-sandboxed tasks route to plain compute lanes (cheaper, faster)

## What "fully integrated" means (checklist)

- [x] Host binary builds clean, cooperative runs proven
- [x] Receipt schema defined (PL-compatible)
- [x] Threat model written (enforced / assumed / unmitigated)
- [x] Integration architecture (this doc)
- [x] Dev-graph epic + dashboard visibility
- [ ] Exchange lane adapter: register `organelle-host` lane kind
- [ ] Governor policy: route sandboxed tasks → host lanes
- [ ] End-to-end: governor → exchange → host → PL receipt → CANON
- [x] Hostile tests (tests/hostile/a-i + tests/evidence/run-hostile.sh;
  full-stack runs 2026-10-10, see docs/10-10-SECURITY.md §3)

## Honest boundaries

- Cooperative guests: PROVEN. Hostile probes (a-i) run against the full stack:
  fork bombs, thread floods, FD leaks, output floods, root writes all
  contained or fail-closed (docs/10-10-SECURITY.md §3). Adaptive adversary:
  still UNKNOWN by design — probes test specific invariants, not all attacks.
- The seccomp filter is correctly constructed (isolated filter test) but the
  raw-syscall bypass was never executed against the full stack.
- No claims about kernel exploits, side channels, or container escapes.
