# Threat Model — litebox-organelle-host (hardened pilot)

**Date:** 2026-10-08
**Scope:** Cooperative-guest pilot. This is NOT a claim of containing malicious agents.

## 1. Architecture: two layers

```
┌─────────────────────────────────────────────────────────────┐
│ OUTER SANDBOX (kernel-enforced, this binary)                │
│  • user ns (0 → 65534/nobody)                               │
│  • mount ns (empty root; NO bind mounts — allowlist via read-only   │
│    guest tar; /tmp)                                             │
│  • pid ns (child is PID 1)                                  │
│  • net ns (zero interfaces)                                 │
│  • seccomp-BPF deny-by-default → KILL_PROCESS               │
│  • all capabilities dropped; setuid(nobody)                 │
│  • RLIMIT_AS + RLIMIT_CPU                                   │
│  • watchdog (SIGKILL on timeout)                            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ INNER: LiteBox linux_userland (OS personality)        │  │
│  │  • syscall rewriting (static, best-effort)            │  │
│  │  • virtual FS (tar_ro + in_mem); no TUN device       │  │
│  │  • shim telemetry (syscall + file-open log)           │  │
│  │  • platform seccomp filter (stacked, inner)           │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 2. What each layer trusts / enforces

### Outer sandbox
| Mechanism | Trusts | Enforces |
|---|---|---|
| User namespace | Kernel userns isolation | Child is nobody(65534) on host; no host privilege |
| Mount namespace | Kernel mount isolation | Child sees empty root + tmpfs /tmp only; no /proc, /sys, /dev. Allowlist files are NOT bind-mounted (the nobody-mapped child gets EPERM on the bind remount-ro); they reach the guest exclusively via the read-only guest tar (TarRo layer). |
| PID namespace | Kernel pid isolation | Child cannot see/signal host processes |
| Net namespace | Kernel net isolation | Zero interfaces → no packets can leave/enter |
| seccomp-BPF (deny→kill) | Kernel seccomp | Only allowlisted host syscalls; everything else kills the process. **Cannot be bypassed by JIT'd syscalls** — the filter sees the real syscall. |
| Capability drop + setuid | Kernel creds | No capabilities in any namespace; uid 65534 |
| RLIMIT_AS / RLIMIT_CPU | Kernel rlimits | Hard memory/CPU caps; SIGKILL on exceed (CPU) |
| Watchdog | Parent process | SIGKILL if wall-clock exceeds timeout_secs |

### Inner (LiteBox)
| Mechanism | Trusts | Enforces |
|---|---|---|
| Syscall rewriter | Static analysis of ELF | Guest `syscall` insns → shim trampolines (best-effort) |
| Virtual FS | Shim path resolution | Guest sees only tar contents + /tmp |
| No TUN | Shim net stack config | Guest socket() has no backend (hangs → watchdog) |
| Shim telemetry | In-process logging | Observation for receipts, NOT enforcement |

## 3. The 5 red-team findings → mitigations

### R1 — Shared address space, no memory isolation
**Was:** LiteBox linux_userland runs the guest in the host process's address space.
**Mitigation:** The guest now runs in a *separate process* (cloned child) with its own
address space, in its own PID/user/mount/net namespaces. A guest memory corruption
can only corrupt the child process, which the parent can kill and which has no
host privileges. The inner LiteBox address-space sharing remains, but its blast
radius is now the unprivileged child.
**Residual:** None for the cooperative pilot beyond the child's own integrity
(which the outer layers contain).

### R2 — Syscall rewriter is not a security boundary (bypass via JIT'd syscalls)
**Was:** A guest could emit a `syscall` instruction at runtime (or via `int $0x80`),
bypassing the static rewriter and invoking host syscalls directly.
**Mitigation:** The outer seccomp-BPF filter is deny-by-default at the **kernel** level.
A runtime-generated `syscall` still traps to the kernel, and the kernel evaluates it
against the filter. Non-allowlisted syscalls → `SECCOMP_RET_KILL_PROCESS` (SIGSYS).
The rewriter is now correctly labeled **best-effort**; seccomp is the enforcement.
**Proven by:** hostile test (b) — runtime-generated `socket` syscall → process killed
by SIGSYS. Receipt records `signal(SIGSYS)`.
**Residual:** The allowlist itself (what the LiteBox runner needs). A bypassed
*allowlisted* syscall (e.g. `read`/`write` on an attacker fd) is still possible in
theory, but fds available to the guest are limited to stdio/pipes/telemetry.

### R3 — No namespaces, no chroot, no Landlock, no capability dropping
**Was:** The LiteBox runner ran with full host visibility.
**Mitigation:** User + mount + PID + net namespaces; pivot_root to an empty root
with a tmpfs /tmp (no bind mounts — the allowlist travels exclusively via the
read-only guest tar, since the nobody-mapped child cannot bind-mount read-only:
EPERM on the remount, fixed 2026-10-10); all capabilities dropped;
setuid(nobody). Landlock: **conditional** — measured per-run via
/sys/kernel/security probe; enforced only where the kernel exposes it, and the
receipt states the measured result honestly (the old hard-coded "kernel does not
expose it" was wrong on kernels that do; fixed 2026-10-10, commit 0628b2d).
**Proven by:** hostile tests (a) /proc/self/mem → ENOENT, (d) write outside
allowlist → ENOENT/EROFS.

### R4 — Network all-or-nothing via TUN
**Was:** Network allow/deny was a single TUN toggle.
**Mitigation:** Two independent denials: (1) LiteBox platform created with
`tun_device_name=None` (no backend); (2) the child is in a net namespace whose
interface list is measured per-run (observed: `lo` only — the old "zero
interfaces, not even loopback" slogan was false; fixed 2026-10-10, commit
0628b2d). A guest socket() via the shim has no backend; a raw host socket()
is killed by seccomp; the measured interface list is in the receipt, not a
slogan.
**Proven by:** hostile test (c) — shim socket() with no TUN → watchdog timeout;
raw socket() → SIGSYS.

### R5 — No documented threat model
**Was:** No written threat model.
**Mitigation:** This document. It states what is enforced, what is trusted, what
is NOT mitigated, and what is out of scope.

### R6 — No-TUN connect wedges the runner (hang)
**Mitigation:** The parent watchdog (`wait_with_timeout`) SIGKILLs the child if
wall-clock exceeds `timeout_secs`. A hanging guest produces a `timeout` receipt,
not a wedged host.
**Proven by:** hostile test (c).

## 4. Explicitly NOT mitigated (honest)

- **Landlock:** conditional — measured per-run via /sys/kernel/security probe
  (observed available on this kernel 2026-10-10). Enforced only where exposed;
  the receipt states the measured result. Not a universal guarantee.
- **cgroups v2:** not writable in this environment. RLIMIT_AS + RLIMIT_CPU used.
  (RLIMIT_AS caps virtual address space, which is the practical OOM lever for a
  single process; it does not account page cache or provide the observability
  of cgroups.)
- **`/proc` hiding inside LiteBox:** the inner virtual FS has no /proc; the outer
  mount ns has no /proc either. Both layers agree.

## 5. Out of scope (do NOT claim)

- **Kernel exploits.** A kernel privilege-escalation vulnerability defeats all
  namespaces/seccomp. This pilot does not defend against kernel exploits.
- **Microarchitectural side channels** (Spectre/Meltdown-class, cache timing).
  Not defended; not measured.
- **Malicious guests.** The pilot is **cooperative-guest only**. The hostile tests
  demonstrate that *specific* escape attempts fail; they do not prove containment
  of an adaptive adversary. Do not extrapolate.
- **Resource exhaustion of the host** beyond the child's rlimits: fork bombs
  contained — default-deny kills clone at the outer filter (hostile test g:
  all 3000 fork attempts denied, clean exit); with allow_clone=true the
  guest is SIGSYS-killed at ~5-16 threads, well before RLIMIT_NPROC=64
  (hostile test g2, 2026-10-10 closeout). Fail-closed in both modes; exact
  SIGSYS syscall unattributed (residual).
- **Covert channels** via timing, exit codes, or resource usage.
- **Supply chain:** the guest tar is built from host files; a compromised host
  binary compromises the guest. The tar_hash in the receipt identifies *what ran*,
  not that it was benign.

## 6. What the tests prove (and only this)

| Test | Proves |
|---|---|
| Cooperative /bin/echo | The sandbox runs a benign program; receipt fields populate; telemetry works. |
| (a) /proc/self/mem | Neither inner nor outer layer exposes host /proc to the guest. |
| (b) raw syscall bypass | A JIT'd `syscall` for a non-allowlisted call is killed by the kernel (SIGSYS). The rewriter bypass is *detected and stopped* at the outer layer. |
| (c) socket | No network path exists (shim has no TUN; raw socket killed). |
| (d) write outside allowlist | The guest cannot write outside its virtual FS; the host mount ns exposes nothing writable except /tmp. |
| (e) memory exhaustion | RLIMIT_AS caps the child's address space; the OOM is contained. |

Each test's receipt records the denial. **Claim only what the tests prove.**

### Rigor application (2026-10-10, brutal-audit rollout R-1/R-7/R-8)

- **R-1 (instance-only):** every "Proven by hostile test (x)" claim above is
  `class_scope: instance-only`. Each hostile test proves one specific attack
  shape fails; none proves containment of an adaptive adversary (see §5:
  "Malicious guests" is out of scope — do not extrapolate).
- **R-7:** the hostile tests are PROPERTY tests for their stated invariant
  ("a JIT'd syscall for a non-allowlisted call is killed by the kernel"),
  run manually against the built binary. They are NOT wired into `cargo test`
  (0 `#[test]` in this repo). Their record is this document's table, not a CI
  gate — read §6 as the test log.
- **R-8 (honestly-unsigned):** `receipt.json` is an observation log, not a
  signed artifact. It carries hashes (artifact_hash, policy_hash, tar_hash)
  and a `caveats[]` field for what was NOT proven. Its verification power is
  "the operator can re-check the hashes", not provenance. Do not present a
  receipt as proof of guest benignity — per §5, tar_hash identifies what ran,
  not that it was benign.
