# AUDIT-APPLICATION — litebox-organelle-host

**Slice:** brutal-audit rollout 3/8  
**Date:** 2026-10-10  
**Repo:** litebox-organelle-host (~/workspace/litebox-organelle-host)  
**Audited at:** Git HEAD 1c5fd1b  
**Commit:** TBD (doc-only; changed files: threat-model.md, this file; src/sandbox.rs left alone)

## Deconfliction

A separate hardening coordinator is actively working this repo. External review landed 2026-10-10 ~15:10 PDT: 4.0/10. P0: `ldd` runs on untrusted binaries pre-sandbox. P1s: unbounded guest output, unrestricted `clone`/`clone3`, unauthenticated manifest, inherited FDs. P2s: receipt telemetry/digest gaps. `INTEGRATION.md` vs `threat-model.md` hostile-test claims disagree.

This pass is doc-only in `threat-model.md`. Code was not touched; `src/sandbox.rs` is mid-edit by the coordinator and was left alone.

## What this is

Rust sandbox host for running organelle guest bundles: outer kernel sandbox (user/mount/pid/net namespaces, seccomp-BPF deny-by-default, rlimits, watchdog) + inner LiteBox `linux_userland` (syscall rewriting best-effort, virtual FS, shim telemetry). Emits PL-style `receipt.json` per run. Cooperative-guest pilot only — **NOT** a claim of containing malicious agents.

## Per-finding application

### R-1 — APPLIED (verdict: PROVEN)
Appended to `threat-model.md` §6 (2026-10-10): every “Proven by hostile test (x)” claim is `class_scope` instance-only — each hostile test proves one specific attack shape fails; none proves containment of an adaptive adversary; do not extrapolate. Malicious guests are out of scope per §5.

### R-2 — PROVEN (already exemplary; no change needed)
`threat-model.md` §4 “Explicitly NOT mitigated” (Landlock, cgroups v2), §5 “Out of scope (do NOT claim)” (kernel exploits, side channels, malicious guests, host resource exhaustion, covert channels, supply chain), §6 ending “Claim only what the tests prove.”

### R-3 — N/A (not applicable)
No hash-chained log. `receipt.digest()` supports chaining, but no persistent chain file exists in-repo.

### R-4 — N/A in-repo
No defect backlog in this repo. The external review findings (4.0/10) are owned by the hardening coordinator, not triaged here.

### R-5 — N/A (not applicable)
No signature/denylist/strip pattern games. The seccomp allowlist is a kernel mechanism, not a pattern list.

### R-6 — PROVEN (already satisfied; no change needed)
Shim telemetry is explicitly “observation for receipts, NOT enforcement” (`threat-model.md` §2). Receipt’s named consumer is the proof ledger per `INTEGRATION.md`; denial observations are consumed by the hostile-test evidence table in §6.

### R-7 — APPLIED (verdict: PROVEN)
Appended to `threat-model.md` §6: hostile tests (a)-(f) are manually-run PROPERTY tests for their stated invariant, NOT wired into `cargo test` (0 `#[test]` in this repo); their record is the §6 table, not a CI gate.

### R-8 — APPLIED (verdict: PROVEN)
Appended to `threat-model.md` §6: `receipt.json` declared honestly-unsigned — an observation log, not a signed artifact; carries hashes (`artifact_hash`, `policy_hash`, `tar_hash`) and a `caveats[]` field for what was NOT proven; verification power is “the operator can re-check the hashes”, not provenance; `tar_hash` identifies what ran, not that it was benign.

### R-9 — N/A (not applicable)
No claim/falsification log in-repo.

### R-10 — FLAGGED (verdict: DISPROVEN)
Staleness found and flagged, not fixed here to avoid edit collision with the coordinator: `tests/hostile/f_output_flood.c` exists and is tracked, but the §6 table lists only tests (a)-(e). The doc lags the tests.

### R-11 — UNKNOWN (verdict: UNKNOWN)
See Explicit UNKNOWN list (R-11) below.

### R-12 — PROVEN
No unsourced oral footnotes found in my read.

## Commits

- Changed files: `threat-model.md`, this file (`AUDIT-APPLICATION.md`)
- Commit hash: TBD
- `src/sandbox.rs` intentionally untouched (coordinator mid-edit)

## Test results

Not run — 0 `#[test]` in the repo. Hostile tests are manually-run C binaries; the coordinator owns the run. Untracked compiled binaries in `tests/hostile/` are build artifacts, not committed.

## Wont-fix list (R-4)

None in-repo. External review findings (4.0/10) are owned by the hardening coordinator; no local defect backlog exists to triage here.

## Explicit UNKNOWN list (R-11)

1. `INTEGRATION.md` vs `threat-model.md` hostile-test claim disagreement flagged by the external review ~15:10 PDT — which claims disagree was not verified by me.
2. Whether hostile tests (a)-(f) currently pass against the coordinator’s in-progress `sandbox.rs`.
3. Production readiness — pilot only; cooperative guests only.

*Note added during this pass:* the coordinator has since added hostile tests
`(g) forkbomb` and `(g2) thread_quota` (tracked `.c` sources, untracked
binaries) — the §6 table now lags by three tests, not one. Still flagged, not
fixed here.

## Top critical issues

1. External review P0/P1s owned by the hardening coordinator: `ldd` runs on untrusted binaries pre-sandbox; unbounded guest output; unrestricted `clone`/`clone3`; unauthenticated manifest; inherited FDs.
2. `INTEGRATION.md` vs `threat-model.md` hostile-test claim disagreement — flagged by external review, not yet verified.
3. Hostile tests are not CI-wired (`0 #[test]`), so the §6 table can drift; `f_output_flood` is already tracked in tests but missing from the §6 table.
4. Receipts are unsigned; verification is operator hash re-check only, not provenance.
