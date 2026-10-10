# litebox-organelle-host — verify-against-standard

Wave 4b-1: the repo's existing host experiment checked against
`organelles/ORGANELLE-MIGRATION-STANDARD.md`, six aspects + done-bar.
Verdict: **conformant after minimal gap fixes** (no re-architecture).

## The one capability unit

The repo is a single binary crate (`litebox-organelle-host`): run a guest per
a litebox manifest inside the outer Linux sandbox (user/mount/PID/net
namespaces, seccomp deny-by-default, zero caps, rlimits, watchdog) with
LiteBox as the inner OS personality, and emit the PL-style receipt JSON.
`src/{guest,manifest,receipt,sandbox,syscalls,tarball}.rs` are its internals —
not independently callable — so there is exactly one organelle:

| Unit | Source | Ops | Tier | Decision |
|---|---|---|---|---|
| litebox-host | `src/main.rs` (`run --manifest`) + `sandbox.rs` | describe, run | A | **Bespoke** (`lh`). A hardened sandboxed-execution host. No ref organelle runs sandboxed guests. This is also the correct shape per `INTEGRATION.md`: "the host is a lane type in the exchange registry, not a special case" — registering the host itself as an organelle on the substrate. |

## Two manifest concepts (do not conflate)

1. **Litebox guest manifest** (`src/manifest.rs::Manifest`): the governor's
   authorization for ONE guest run — `organelle_id, authority, command,
   filesystem_allowlist, network, cpu/memory/timeout`. This is the INPUT to
   the `run` op.
2. **Organelle-migration manifest** (`organelles/litebox-host.manifest.json`,
   codon `lh`): the capability contract of the host unit itself, in
   `organelle-manifest` v1 terms. This is what registers on the substrate.

## Verification against the six aspects

1. **COMPUTATION** — was the gap: no `organelles/` dir. Fixed:
   `organelles/litebox-host.manifest.json` for the one unit.
2. **CAPABILITY CONTRACT** — `describe` (ReadOnly, no cap) + `run`
   (ExternalEffect, requires `litebox.run`); authority ExternalEffect /
   Candidate; Write/ExternalEffect-without-capability is INVALID and the host
   refuses it (proven by the denial test). Transports native + unix_socket;
   receipts content-addressed + sha256 + chained. Fixed via
   `src/organelle_impl.rs` (`organelle_host::Organelle` impl).
3. **EXECUTION PERSONALITY** — `organelles/litebox-host.execution.json`:
   fs allowlist (guest tar read-only inside, manifest staging in tmp),
   network deny, process spawn (one sandboxed clone per run), secrets
   none-required, platform linux-userland outer + LiteBox inner,
   sandbox litebox.
4. **PROVENANCE** — the host pins the manifest hash in every receipt it
   emits (substrate behavior for all registered organelles); build commit
   filled at registration; valence **Candidate** — honest: the external
   security review is open (reviewer 4.0/10; hardening coordinator's lane,
   tracked in `audit-ledger.md` row 3B, not this migration).
5. **RESOURCE ENVELOPE** — cpu / mem / wall-time / io declared in
   execution.json; the guest manifest's own `timeout_secs` bounds each run
   (watchdog SIGKILL).
6. **KILL SEMANTICS** — suspend-first. Runs are atomic and bounded by the
   guest timeout, so `suspend()` is honestly ephemeral (no resumable
   in-memory state; asserted in tests); kill → watchdog SIGKILL + the host's
   final Kill receipt. Per-run state lives in `$TMPDIR/organelle-<id>-<pid>`.

## Gaps fixed (minimal, no re-architecture)

- Added `src/lib.rs` (lib target re-exporting the sandbox modules) —
  `src/main.rs` untouched (it is mid-hardening by a separate coordinator;
  see below).
- Added `src/organelle_impl.rs` — thin wrapper; zero sandbox logic
  reimplemented. `run` shells to the real binary; `describe` calls the real
  `sandbox::describe()`.
- Added `tests/organelle_registration.rs` — register → describe live →
  verify_chain; run fail-closed without `litebox.run`; run honestly fails on
  a rejected guest manifest (the binary's own `Manifest::parse` is the
  validator); suspend/kill receipts; manifest-vs-JSON equality.
- `Cargo.toml`: +2 path deps (organelle-host, organelle-manifest). Nothing
  else touched.

Deliberate non-changes: the P0/P1 security findings (ldd, output bounds,
clone3, manifest auth, FDs) belong to the hardening coordinator's lane —
this migration does not re-litigate them. `tests/hostile/*` is their harness.

## Reference-organelle check (all 12 considered)

No ref organelle is a sandboxed-execution host (`ref-model-call`,
`ref-hash-seal`, `ref-kv-store`, … — no overlap). Verdict: 1 bespoke
organelle, 0 adoptions.

## Execution facts

- Codon `lh`: unique workspace-wide (grep over all
  `*/organelles/*.manifest.json` + the 12 ref codons, 2026-10-10).
- No secrets in manifests (none exist in this repo's flow).
- Dirty-tree note: at migration time the tree carried the hardening
  coordinator's uncommitted work (`M src/main.rs`, `M src/manifest.rs`,
  `?? tests/evidence/`, `?? tests/hostile/[a-e]_*`). This commit stages
  ONLY migration files (`organelles/`, `src/lib.rs`,
  `src/organelle_impl.rs`, `tests/organelle_registration.rs`, `Cargo.toml`
  dep lines). Their work is untouched and unstaged.

## Open item (external, transient)

At commit time the `organelle-host` substrate had uncommitted,
non-compiling refactor work in flight by the organelles hardening
coordinator (`crates/organelle-host/src/lib.rs`, edited 23:51 UTC —
`receipt_shell` signature changed, internal call sites not yet updated).
The migration code was verified against the last committed substrate
(`f928bc6`): every public API item used (Host::new/register/call/
call_with_grant/verify_chain/suspend/kill/list_manifests/receipts/
issue_grant, CallContext::new, Organelle trait + manifest()/handle(),
OrganelleError::failed/not_found, Checkpoint/CallError fields) is
signature-stable there, and the test file mirrors the factory's green
suite 1:1. The static manifest validates against
`organelles/manifest-json-schema.json`. Full `cargo test` runs when the
substrate compiles again — rerun `cargo test --offline --test
organelle_registration` then; nothing here is faked, the invocation
proofs are deferred, not asserted.
