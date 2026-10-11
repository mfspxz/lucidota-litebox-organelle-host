# LiteBox Organelle Host: the road to 10/10 security

**Status:** hardening campaign complete through the reviewer's full 8-item repair order (2026-10-10).
**Revision:** `51e2eea` (seven fix commits: `c8a45e2` → `47a1b5a` → `69fa52c` → `1886ee8` → `31acb15` → `0628b2d` → `51e2eea`).
**External review baseline:** 4.0/10 overall (2026-10-10 ~15:10 PDT).
**This document:** what 10/10 means per category, which gaps the campaign closed (each hostilely verified), what remains, milestones with acceptance tests, and how re-audit works. It does not claim 10/10.

**Scope note:** this covers the *wrapper* (host-side sandbox construction, manifest authentication, receipt honesty). The upstream Microsoft LiteBox 0.1 library (the inner syscall shim) is tracked separately — including its known root-write permission issue (`can_change_entries_in_dir` returning true for `None` metadata), which is NOT fixed here and is NOT conflated with wrapper findings.

Evidence: `tests/hostile/` (probes a–i, rebuilt from source 2026-10-10), `tests/evidence/run-hostile.sh`, `receipts/ledger.jsonl` (hash-chained).
**Suite:** 42 passed, 0 failed (17 lib + 19 bin + 6 integration).

---

## 1. Threat model

**Adversaries:**
- **A1 — malicious guest program:** runs inside the sandbox. Goal: escape containment, exhaust host resources, exfiltrate via inherited FDs, forge receipts, lie about completion.
- **A2 — malicious manifest author:** supplies a crafted manifest. Goal: escalate resource limits, enable cloning, spoof authority, bind a different program than authorized.
- **A3 — careless operator:** misreads receipts, trusts unverified authority labels, deploys without checking.

**Assets:** host integrity, resource bounds, receipt chain (evidence), authority grants.

**Trust boundaries:**
1. **Host boundary** (operator → `litebox-organelle-host run`): manifests are untrusted input until Ed25519-verified. Without `--trusted-key`, the host runs in local mode and the receipt marks authority `UNVERIFIED` — labels are never presented as grants.
2. **Sandbox boundary** (host → guest): namespaces, seccomp deny-by-default, rlimits, FD hygiene. The guest's syscalls are rewritten by the LiteBox shim (best-effort); the outer seccomp-BPF filter is the kernel-enforced backstop.
3. **Upstream LiteBox 0.1:** explicitly NOT a security boundary — research-grade (proof boundary 4/10 per Oct-10 review). The wrapper treats it as an untrusted inner layer.

**Explicitly out of scope:** kernel exploits, microarchitectural side channels, host binary compromise, the upstream LiteBox permission model (tracked separately).

---

## 2. What 10/10 means per category

| Category | 10/10 bar | Campaign exit (honest) |
|---|---|---|
| Binary execution hygiene | Host never executes untrusted bytes; dep discovery is pure parsing | **Closed** — `ldd` fully removed; ELF64 PT_INTERP/DT_NEEDED parsed, never executed; hostile interp never runs |
| Output containment | Guest cannot OOM the parent via stdout/stderr floods | **Closed** — parent-side byte budgets (16MiB default), incremental hashing, truncation honestly receipted |
| Task-creation control | Guest cannot fork-bomb or thread-flood the host | **~8** — default-deny proven; fail-closed at scale proven; exact SIGSYS attribution unknown (§4.1) |
| Manifest authenticity | Only governor-signed manifests carry authority; tampering rejected | **Closed** — Ed25519 over canonical manifest bytes; tampered/wrong-key/expired all rejected |
| FD hygiene | Guest sees exactly stdio; no inherited capabilities | **Closed** — explicit FD table, `sanitize_fds(&[])`, hostile probe confirms |
| Receipt honesty | Receipts distinguish observed / unavailable / not-measured; never zero-as-unknown | **Closed** — Option fields, null-with-reason, measured (not sloganeered) claims |
| Receipt integrity | Tamper-evident, hash-chained, canonical digest over all fields | **Closed** — `litebox-receipt/1`, SHA-256 over canonical JSON of every field, append-only ledger |
| Hostile equivalence | Every fix proven against live hostile probes, not just unit tests | **Strong** — 9 probes vs full stack; docs reconciled (§5) |

---

## 3. Gaps closed by this campaign

- **P0 — host-side `ldd` on untrusted ELF** (`c8a45e2`): `ldd` executes its target (LD_TRACE_LOADED_OBJECTS, with direct-execution fallback). Now: pure ELF64 parsing of PT_INTERP + DT_NEEDED; sonames resolve via fixed search dirs only; non-ELF yields no deps without execution; malformed ELF fails closed; traversal sonames refused. 5 regression tests. Tar hash byte-identical to ldd path on /bin/echo.
- **P1 — unbounded guest output** (`47a1b5a`): `read_all()` grew a `Vec<u8>` without bound; guest RLIMIT_AS doesn't constrain parent allocations. Now: `drain_bounded()` streams each pipe through an independent budget (manifest `stdout_limit_bytes`/`stderr_limit_bytes`, default 16MiB), hashes incrementally (O(1) parent memory), spills retained prefix to workdir, records stored/observed/truncated. **Hostile proof (2026-10-10):** `f_output_flood` emitted 727MB; parent truncated at 16MiB budget; receipt `timeout` + `stdout_truncated=true` with honest byte counts and artifact_hash-covers-prefix caveat.
- **P1 — unrestricted clone/clone3** (`69fa52c`): PID namespace limits visibility, not host resources. Now: outer seccomp filter denies clone/clone3 by default (KillProcess); `allow_clone` (default false, governor-authorized, signature-bound) permits; `max_processes` (default 64) sets RLIMIT_NPROC as defense-in-depth. **Hostile proof:** `g_forkbomb` (libc fork + JIT'd raw clone) — all 3000 attempts denied, clean exit, no host impact. `g2_thread_quota` with allow_clone=true: SIGSYS-killed at ~5–16 threads, fail-closed (§4.1).
- **P1 — unauthenticated manifest** (`1886ee8`): the manifest's authority string was a caller claim. Now: `--trusted-key <hex>` enables strict mode — manifest must carry an auth block (issuer, issued_at, expires_at, invocation_id, Ed25519 signature) over canonical manifest bytes (signature blanked). Covers command, allowlist, limits, allow_clone, program_sha256. Expiry enforced (±300s skew). Without the key: local mode, receipt marks `UNVERIFIED(local-mode)` + caveat. **Hostile proof (2026-10-10):** Python signer ↔ Rust verifier agree; valid → `auth_status: verified`; tampered command → `grant signature invalid; rejected` (exit 1); tampered limit → sanity ceiling rejection.
- **P1 — inherited file descriptors** (`31acb15`): child inherited unaccounted FDs; seccomp allows read/write without FD restrictions. Now: explicit FD table in child_entry — error fd closed after logging, stdin → /dev/null, `sanitize_fds(&[])` closes everything ≥3. Setup report written pre-filter, fd closed before guest runs (guest cannot forge measurements). **Hostile proof:** `h_fd_leak` → "OK: no fds beyond stdio are readable".
- **P2 — receipt telemetry dishonesty** (`0628b2d`): receipt reported `syscalls_allowed: []` and `syscall_total: 0` when the shim exposes no telemetry API — absence of evidence as evidence of absence. Now: telemetry fields are `Option`; unavailable → null with `telemetry_status: 'unavailable: <reason>'` + caveat. Network claim from measured interface list (was false "zero interfaces" slogan; net ns actually has `lo`). Landlock caveat conditional on measured probe (old hard-coded "kernel does not expose it" was wrong; this kernel exposes it).
- **P2 — receipt digest gaps** (`51e2eea`): old digest hashed 5 fields, omitting authority, telemetry, caveats. Now: `receipt_version: 'litebox-receipt/1'`; SHA-256 over canonical JSON (sorted keys) of every field except the digest itself; `verify_digest()`; tampering any field breaks verification (unit-tested). Every sealed receipt appends to `receipts/ledger.jsonl` (hash-chained, tamper-evident; 18 entries, chain verified 2026-10-10).

**Suite:** 42 passed, 0 failed (17 lib + 19 bin + 6 integration), down from a pre-campaign baseline that lacked the security tests entirely.

---

## 4. What remains (residuals — the honest list)

1. **Thread-quota SIGSYS unattributed (UNKNOWN).** With `allow_clone=true`, guests die by SIGSYS at ~5–16 threads — well before RLIMIT_NPROC=64. Fail-closed is proven (no host impact, no runaway), but the exact killing syscall is unattributed. Leading hypothesis: glibc clone-fallback vs inner filter interaction. RLIMIT_NPROC is correctly set (verified in setup_report.json) but was never observed as the binding constraint. **Not a containment hole** — the guest is more restricted than the quota, not less — but the mechanism should be identified.
2. **Upstream LiteBox root-write permission (KNOWN, OUT OF SCOPE).** Hostile probe `i_root_write` confirms: a non-root guest can create entries at `/` on the overlay root (upstream `resolver.rs can_change_entries_in_dir` returns true for `None` permission metadata). Tracked separately against upstream Microsoft LiteBox. **Not fixed here; not conflated.**
3. **`host_bin` is caller-supplied** (`src/organelle_impl.rs:105`). The organelle adapter executes the path from `input.host_bin` without verifying it is the genuine host binary. In the governor-mediated threat model the governor is trusted, so this is acceptable — but a compromised/misconfigured caller could point it at an arbitrary binary. Worth a path-canonicalization or binary-hash check in a future pass.
4. **No cgroup enforcement.** cgroups v2 not writable in this environment; containment rests on RLIMIT_AS + RLIMIT_CPU + RLIMIT_NPROC. Documented, not fixed.
5. **Upstream LiteBox 0.1 is research-grade.** Proof boundary 4/10 per Oct-10 review. The wrapper treats it as untrusted; any upstream soundness bug is a wrapper-visible incident, not a wrapper-preventable one.
6. **No independent re-audit yet.** Everything above is builder-tested (closeout audit by a second agent, 2026-10-10). An independent party has not re-run the hostile matrix.

### 2026-10-10 Phase 2 host fix (allowlist EPERM) — residuals added

7. **Upstream LiteBox has no /proc/self/exe (KNOWN, OUT OF SCOPE).** After the
   host fix, hayabusa loads and executes as a guest but panics at
   `src/detections/configs.rs:36` (`current_exe().unwrap()`: "no /proc/self/exe
   available"). LiteBox's virtual FS has no /proc backend, TarRo skips
   symlinks, `InitialNode` has no symlink variant, and the `Backend` trait is
   `Sealed` (not implementable outside the litebox crate) — so no host-side
   synthesis is possible without forking upstream. Any guest that calls
   `current_exe()` (or otherwise needs /proc) cannot run until upstream gains
   a /proc personality. Tracked separately against upstream Microsoft LiteBox,
   like residual #2.
8. **Guest-allocator compat shims in guest env (DONE, documented).**
   `MIMALLOC_ALLOW_THP=0` + `MIMALLOC_LARGE_OS_PAGES=0` are set in the minimal
   guest env: mimalloc (hayabusa's allocator, `MI_DEFAULT_ALLOW_THP=1` on
   Linux) issues `madvise(MADV_HUGEPAGE)`, which the LiteBox platform's memory
   manager does not implement (`mm.rs:920` `unimplemented!` → platform panic
   → SIGSYS). The hint is advisory (the kernel may ignore it too), so
   disabling it changes no containment property. The correct upstream fix is
   for `sys_madvise` to no-op advisory hints instead of panicking; filed
   alongside residual #7.
9. **Tar format is USTAR, not GNU (FIXED this change).** `build_guest_tar`
   used `Header::new_gnu()`; the guest's tar parser (`tar_no_std`, upstream)
   does not understand GNU 'L' (longname) entries — worse, its entry iterator
   silently *terminates* at the first 'L' entry, dropping every later entry
   from the guest FS index. Any allowlist path >100 chars (e.g. hayabusa's
   `rules/config/data_mapping/*.yaml`) made the loader/interp libs vanish →
   `load_program failed: ENOENT`. Now: `Header::new_ustar()` (prefix-splitting,
   understood by `tar_no_std`) + an explicit fail-closed guard refusing guest
   paths >255 bytes. Pinned by the `guest_reads_allowlisted_file_end_to_end`
   regression test shape (non-empty allowlist — the exact hole Phase 1
   missed).

---

## 5. Milestones to 10/10 (each with acceptance tests)

- **M1 — attribute the thread-quota SIGSYS.** Identify the exact syscall killing guests at 5–16 threads with allow_clone=true (strace with SECCOMP_RET_TRAP, or filter-instrumentation build). *Acceptance:* named syscall + which filter kills it, documented; or RLIMIT_NPROC demonstrated as the binding constraint via a probe that reaches EAGAIN.
- **M2 — independent re-audit.** External reviewer re-runs the hostile probes (a–i, rebuilt from source) + full suite on this HEAD, confirms or refutes each §3 claim. *Acceptance:* signed note; audit-ledger row updated.
- **M3 — `host_bin` binding.** Canonicalize the adapter's `host_bin` path and verify it against an expected hash or allowlisted directory. *Acceptance:* hostile test with a substituted binary path is rejected.
- **M4 — upstream LiteBox upgrade.** When upstream fixes the root-write permission model (or the wrapper gains its own overlay permission layer), re-run `i_root_write` → NOT-REACHABLE. *Acceptance:* probe exit 0 with "NOT-REACHABLE".
- **M5 — cgroup enforcement.** Where the kernel exposes cgroup v2 delegation, apply memory/pids controllers as the primary quota mechanism with rlimits as fallback. *Acceptance:* probe exceeding the pids controller limit is contained by the controller, with the mechanism named in the receipt.

---

## 6. Documentation reconciliation (2026-10-10 closeout)

The campaign fixed code first; docs lagged. Reconciled:
- `threat-model.md` R3: Landlock "not mitigated / kernel does not expose it" → **conditional**, measured per-run (this kernel exposes it).
- `threat-model.md` R4: "zero interfaces (not even loopback)" → **measured interface list** (`lo` observed); slogan removed.
- `threat-model.md` §5: fork-bomb "not stress-tested" → **stress-tested** (g/g2 hostile proofs, fail-closed).
- `INTEGRATION.md`: "shim telemetry" → **no telemetry API** (fields null/unavailable); "Hostile tests (blocked)" → **run 2026-10-10**; manifest schema and artifact_hash descriptions corrected to match implementation.
- `AUDIT-APPLICATION.md`'s note ("INTEGRATION.md vs threat-model.md hostile-test claims disagree") is now resolved: both documents agree with the implementation as of this revision.

---

## 7. How re-audit works

1. `cargo test` — 42 tests, all must pass.
2. Rebuild probes from source: `cd tests/hostile && for f in *.c; do gcc -O2 -o "${f%.c}" "$f"; done` (stale binaries prove nothing).
3. Run each probe through the full stack: `./target/debug/litebox-organelle-host run --manifest <manifest>` with the probe as `command`; check the receipt's `exit_status`, `timed_out`, truncation flags, and `caveats`.
4. Verify the ledger: every `receipts/ledger.jsonl` entry hash-chains to the previous; `receipt_digest` recomputes over canonical JSON.
5. Tamper tests: sign a manifest with `tests/evidence/sign-manifest.py`, mutate one field, confirm rejection under `--trusted-key`.
