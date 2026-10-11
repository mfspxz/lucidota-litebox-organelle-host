//! Outer sandbox: Linux namespaces + seccomp-BPF + rlimits around the
//! LiteBox guest. This is the REAL security boundary (kernel-enforced).
//!
//! The LiteBox linux_userland South is the *inner* OS personality. This
//! module provides the *outer* containment that addresses R1 (shared address
//! space), R2 (rewriter bypass), R3 (no namespaces), R4 (network), R6 (hang).

use anyhow::{Context, Result, bail};
use nix::sched::{CloneFlags, clone};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::manifest::Manifest;
use crate::receipt::{OuterSandbox, ResourceUsage};

/// Nobody UID/GID for the user namespace mapping.
const NOBODY: u32 = 65534;
/// Child setup failure exit code (distinguishes from guest exit codes).
const SETUP_FAILED: i32 = 127;

/// What the child measured about the sandbox it built (written pre-filter,
/// read by the parent for the receipt). Every field is an observation, not
/// an assumption; a missing/unparseable report becomes "not_measured".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SetupReport {
    /// getpid() == 1 (we are PID 1 in the new PID namespace).
    pub pid_is_one: bool,
    /// Interface names visible in the new net namespace (expect ["lo"]).
    pub net_ifaces: Vec<String>,
    /// RLIMIT_AS read back after apply_rlimits.
    pub rlimit_as: u64,
    /// RLIMIT_CPU read back after apply_rlimits.
    pub rlimit_cpu: u64,
    /// RLIMIT_NPROC read back after apply_rlimits.
    pub rlimit_nproc: u64,
    /// CapEff (hex) before drop_capabilities, from /proc/self/status.
    pub pre_drop_cap_eff: String,
    /// CapEff == 0 after drop_capabilities, via capget.
    pub cap_eff_zero_after_drop: bool,
    /// /sys/kernel/security exists (Landlock availability probe).
    pub landlock_available: bool,
}

/// Configuration for one sandboxed run. Built by the parent, consumed by the child.
pub struct SandboxConfig {
    pub workdir: PathBuf,
    pub manifest: Manifest,
    pub program: String,
    pub argv: Vec<String>,
    /// Pre-created pipes: child stdout/stderr write ends.
    pub stdout_w: RawFd,
    pub stderr_w: RawFd,
    /// Sync pipe: parent signals after writing uid/gid maps.
    pub sync_r: RawFd,
    pub sync_w: RawFd,
    /// File the child writes setup errors to (before guest output starts).
    pub error_path: PathBuf,
}

pub struct SandboxResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub rusage: ResourceUsage,
    pub wall_ms: u64,
}

/// Static capability advertisement for the `describe` op: what this build
/// CAN enforce, not a measurement of any live run. Per-run measured values
/// appear in receipts via describe_measured(). Do not confuse the two.
pub fn advertise() -> OuterSandbox {
    OuterSandbox {
        user_ns: true,
        mount_ns: true,
        pid_ns: true,
        net_ns: true,
        seccomp: "deny-by-default (SECCOMP_RET_KILL_PROCESS)".to_string(),
        landlock: "host-dependent; measured per-run".to_string(),
        resource_limits: "rlimit-based; cgroup v2 if writable; measured per-run".to_string(),
        capabilities_dropped: true,
    }
}

/// What the outer sandbox actually enforced — MEASURED by the child and
/// reported via setup_report.json. Returns the description plus any
/// honesty caveats. A missing/unparseable report yields all-false with an
/// explicit caveat: never convert missing evidence into success claims.
pub fn describe_measured(setup: Option<SetupReport>) -> (OuterSandbox, Vec<String>) {
    let mut caveats = Vec::new();
    match setup {
        Some(s) => {
            let net_ok = s.net_ifaces.iter().all(|i| i == "lo");
            if !net_ok {
                caveats.push(format!(
                    "net namespace has unexpected interfaces: {:?} (expected [\"lo\"])",
                    s.net_ifaces
                ));
            }
            if !s.pid_is_one {
                caveats.push("child is not PID 1: PID namespace setup NOT confirmed".to_string());
            }
            if !s.cap_eff_zero_after_drop {
                caveats.push("post-drop CapEff != 0: capability drop NOT confirmed".to_string());
            }
            (
                OuterSandbox {
                    // The child is alive: clone(CLONE_NEWUSER|CLONE_NEWNS|
                    // CLONE_NEWPID|CLONE_NEWNET) succeeded (else no report).
                    user_ns: true,
                    mount_ns: true,
                    pid_ns: s.pid_is_one,
                    net_ns: net_ok,
                    seccomp: "deny-by-default (SECCOMP_RET_KILL_PROCESS); install returned Ok pre-guest (fail-closed)".to_string(),
                    landlock: if s.landlock_available {
                        "available on host but not used by this pilot".to_string()
                    } else {
                        "unavailable: /sys/kernel/security absent".to_string()
                    },
                    resource_limits: format!(
                        "rlimit AS={} CPU={}s NPROC={} (read back via getrlimit); cgroup v2 not writable in this environment",
                        s.rlimit_as, s.rlimit_cpu, s.rlimit_nproc
                    ),
                    capabilities_dropped: s.cap_eff_zero_after_drop,
                },
                caveats,
            )
        }
        None => {
            caveats.push(
                "setup_report.json missing or unparseable: NO sandbox claim below was measured; all booleans are false (not_measured)".to_string(),
            );
            (
                OuterSandbox {
                    user_ns: false,
                    mount_ns: false,
                    pid_ns: false,
                    net_ns: false,
                    seccomp: "not_measured".to_string(),
                    landlock: "not_measured".to_string(),
                    resource_limits: "not_measured".to_string(),
                    capabilities_dropped: false,
                },
                caveats,
            )
        }
    }
}

/// Parent side: clone the sandboxed child, write uid/gid maps, watchdog.
pub fn run_sandboxed(config: SandboxConfig) -> Result<(SandboxResult, Pid)> {
    // 8MB stack for the cloned child.
    let mut stack = vec![0u8; 8 * 1024 * 1024];
    let flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNET;

    // The clone callback runs in the child. It must not return normally on
    // success (we _exit), but nix::clone expects isize return.
    let mut child_main = || -> isize {
        match child_entry(&config) {
            Ok(code) => code as isize,
            Err(e) => {
                // Best-effort error report before dying.
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&config.error_path)
                {
                    use std::io::Write;
                    let _ = writeln!(f, "child setup failed: {e:?}");
                }
                SETUP_FAILED as isize
            }
        }
    };

    let child_pid = unsafe {
        clone(
            Box::new(&mut child_main),
            &mut stack,
            flags,
            Some(Signal::SIGCHLD as i32),
        )
    }
    .context("clone with namespaces failed")?;
    let child_pid = Pid::from_raw(child_pid.as_raw());

    // Parent: write uid_map / gid_map, then release the child.
    write_id_maps(child_pid).context("writing uid/gid maps")?;
    // Signal the child to proceed.
    {
        let w = config.sync_w;
        let rc = unsafe { libc::write(w, b"x".as_ptr() as *const _, 1) };
        if rc != 1 {
            bail!("failed to signal child via sync pipe");
        }
        unsafe { libc::close(w) };
    }
    // Close our copies of the child's pipe ends.
    unsafe {
        libc::close(config.stdout_w);
        libc::close(config.stderr_w);
        libc::close(config.sync_r);
    }

    Ok((
        SandboxResult {
            exit_code: None,
            signal: None,
            timed_out: false,
            rusage: ResourceUsage { wall_ms: 0, user_ms: 0, sys_ms: 0, max_rss_kb: 0 },
            wall_ms: 0,
        },
        child_pid,
    ))
}

/// Write uid_map/gid_map for the cloned child.
fn write_id_maps(pid: Pid) -> Result<()> {
    let pid_raw = pid.as_raw();
    // setgroups deny first (required for gid_map).
    let _ = std::fs::write(format!("/proc/{pid_raw}/setgroups"), "deny");
    std::fs::write(format!("/proc/{pid_raw}/uid_map"), format!("0 {NOBODY} 1"))
        .context("uid_map")?;
    std::fs::write(format!("/proc/{pid_raw}/gid_map"), format!("0 {NOBODY} 1"))
        .context("gid_map")?;
    Ok(())
}

/// Wait for the child with a timeout. Kills on expiry. Returns rusage.
pub fn wait_with_timeout(pid: Pid, timeout: Duration) -> Result<SandboxResult> {
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        let mut status: i32 = 0;
        let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::wait4(
                pid.as_raw(),
                &mut status,
                libc::WNOHANG,
                &mut rusage as *mut _,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            bail!("wait4 failed: {e}");
        }
        if rc == 0 {
            // Still alive.
            if start.elapsed() > timeout {
                timed_out = true;
                let _ = kill(pid, Signal::SIGKILL);
                // Reap.
                let mut status2: i32 = 0;
                let mut rusage2: libc::rusage = unsafe { std::mem::zeroed() };
                unsafe {
                    libc::wait4(pid.as_raw(), &mut status2, 0, &mut rusage2 as *mut _);
                }
                return Ok(SandboxResult {
                    exit_code: None,
                    signal: Some(libc::SIGKILL),
                    timed_out,
                    rusage: rusage_from(&rusage2),
                    wall_ms: start.elapsed().as_millis() as u64,
                });
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        // Reaped.
        let (exit_code, signal) = parse_status(status);
        return Ok(SandboxResult {
            exit_code,
            signal,
            timed_out,
            rusage: rusage_from(&rusage),
            wall_ms: start.elapsed().as_millis() as u64,
        });
    }
}

fn parse_status(status: i32) -> (Option<i32>, Option<i32>) {
    // WIFEXITED / WIFSIGNALED manual (avoid nix dependency for this).
    if (status & 0x7f) == 0 {
        (Some((status >> 8) & 0xff), None)
    } else if (status & 0x7f) != 0x7f {
        (None, Some(status & 0x7f))
    } else {
        (None, None)
    }
}

fn rusage_from(r: &libc::rusage) -> ResourceUsage {
    ResourceUsage {
        wall_ms: 0, // filled by caller
        user_ms: (r.ru_utime.tv_sec as u64) * 1000 + (r.ru_utime.tv_usec as u64) / 1000,
        sys_ms: (r.ru_stime.tv_sec as u64) * 1000 + (r.ru_stime.tv_usec as u64) / 1000,
        max_rss_kb: r.ru_maxrss as u64,
    }
}

/// Child entry point (runs in the cloned namespaces).
fn child_entry(config: &SandboxConfig) -> Result<i32> {
    // Die if the parent dies (avoid orphans).
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as u64, 0, 0, 0);
    }

    // Wait for the parent to write uid/gid maps.
    {
        let mut buf = [0u8; 1];
        let rc = unsafe { libc::read(config.sync_r, buf.as_mut_ptr() as *mut _, 1) };
        if rc != 1 {
            bail!("sync pipe read failed");
        }
        unsafe { libc::close(config.sync_r) };
    }

    // Open the setup-report + error files BEFORE pivot_root (host paths
    // visible now). The report is written after the sandbox is built but
    // before seccomp filters install (no lseek/ftruncate-class syscalls are
    // available afterwards); the fd is closed before the guest runs so the
    // guest cannot touch it.
    let report_path = config.workdir.join("setup_report.json");
    let report_fd: RawFd = unsafe {
        let c = std::ffi::CString::new(report_path.to_string_lossy().as_bytes())?;
        let fd = libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd < 0 {
            bail!("open setup report failed");
        }
        fd
    };
    // /dev/null for the guest's stdin (no /dev after pivot_root, so open now).
    let devnull_fd: RawFd = unsafe {
        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            bail!("open /dev/null failed");
        }
        fd
    };
    let error_fd: RawFd = unsafe {
        let c = std::ffi::CString::new(config.error_path.to_string_lossy().as_bytes())?;
        let fd = libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd < 0 {
            bail!("open error file failed");
        }
        fd
    };
    // Helper to log child stages/errors (fd survives pivot_root).
    let log_err = |msg: &str| unsafe {
        libc::write(error_fd, msg.as_ptr() as *const _, msg.len());
    };

    // Read the guest tar into memory BEFORE pivot_root, leak for 'static.
    let tar_path = config.workdir.join("guest.tar");
    let tar_data = std::fs::read(&tar_path).context("read guest.tar")?;
    let tar_static: &'static [u8] = Box::leak(tar_data.into_boxed_slice());

    // 0. Resource limits first (no fs dependency), then MEASURE what we
    //    actually built. Every value below is observed, not assumed.
    if let Err(e) = apply_rlimits(&config.manifest) {
        log_err(&format!("apply_rlimits failed: {e:?}\n"));
        return Ok(SETUP_FAILED);
    }
    let mut report = measure_setup()?;

    // 1. Mount namespace setup (pivot_root hides the host).
    if let Err(e) = setup_mounts(config) {
        log_err(&format!("setup_mounts failed: {e:?}\n"));
        return Ok(SETUP_FAILED);
    }

    // 2. Drop all capabilities. (The uid_map already maps us to 65534/nobody
    //    on the host, so an explicit setuid is redundant — and would fail
    //    after we drop CAP_SETUID. In-ns uid 0 with zero caps is powerless.)
    if let Err(e) = drop_capabilities() {
        log_err(&format!("drop_capabilities failed: {e:?}\n"));
        return Ok(SETUP_FAILED);
    }
    report.cap_eff_zero_after_drop = cap_eff_is_zero()?;

    // 4. Redirect stdout/stderr to the parent's pipes (guest output).
    unsafe {
        libc::dup2(config.stdout_w, 1);
        libc::dup2(config.stderr_w, 2);
        if config.stdout_w != 1 {
            libc::close(config.stdout_w);
        }
        if config.stderr_w != 2 {
            libc::close(config.stderr_w);
        }
    }

    log_err("stage: pre-seccomp\n");

    // 5. FD HYGIENE. The child inherits every fd the parent had open: pipe
    //    read ends, the sync pipe, and anything the operator's process held
    //    (secret files, sockets). The seccomp filter allows read/write
    //    without fd restrictions, so an inherited fd is a live capability.
    //    Construct the guest's fd table explicitly:
    //      - setup-error logging is complete: close error_fd;
    //      - stdin becomes /dev/null (never the parent's stdin);
    //      - stdout/stderr are already the parent's pipes;
    //      - everything else is closed. The setup report fd is written and
    //        closed BEFORE this point, so the guest never sees it.
    unsafe { libc::close(error_fd) };
    unsafe {
        libc::dup2(devnull_fd, 0);
        if devnull_fd > 2 {
            libc::close(devnull_fd);
        }
    }

    // Write the setup report now: sandbox built, filters not yet installed
    // (plain write needs no lseek/ftruncate-class syscalls), and the fd is
    // closed before the guest runs so the guest cannot forge measurements.
    {
        let json = serde_json::to_string(&report).context("serialize setup report")?;
        let bytes = json.as_bytes();
        let mut written = 0;
        while written < bytes.len() {
            let rc = unsafe {
                libc::write(
                    report_fd,
                    bytes[written..].as_ptr() as *const _,
                    bytes.len() - written,
                )
            };
            if rc <= 0 {
                bail!("write setup report failed");
            }
            written += rc as usize;
        }
        unsafe { libc::close(report_fd) };
    }
    sanitize_fds(&[]);

    // 6. Outer seccomp filter is applied LATER, in run_guest_inner, right
    //    before the inner filter (after FS setup, like the upstream runner).
    //    See guest.rs.

    // 7. Run the LiteBox guest (inner personality). Never returns normally;
    //    exits the process with the guest's exit code.
    crate::guest::run_guest(config, tar_static)
}

/// Make all mounts private and build an empty root (tmpfs /tmp only).
///
/// NOTE (2026-10-10, Phase 2 host fix): the allowlist is NO LONGER
/// bind-mounted here. The child runs in a user namespace mapped to
/// host nobody (65534); the bind remount-ro
/// (`MS_REMOUNT|MS_BIND|MS_RDONLY`) requires CAP_SYS_ADMIN in the user
/// namespace owning the source superblock (the initial/host userns), which
/// the child does not hold — the kernel refuses with EPERM, so every
/// non-empty allowlist died as child_setup_failed(127). The binds were
/// redundant anyway: the guest's filesystem is the LiteBox virtual FS, an
/// overlay of the in-mem layer over the READ-ONLY tar layer
/// (`TarRo`, see guest.rs `default_fs`) — the host mount namespace is never
/// consulted by guest syscalls. `build_guest_tar` already packs every
/// allowlist file (world-readable, write bits cleared) into `guest.tar`,
/// so the tar channel is the SOLE file-ingress path, with equivalent
/// read-only properties and a strictly smaller host-visible set than the
/// old binds (binds also exposed allowlist paths to raw-syscall bypasses;
/// the empty root exposes nothing).
fn setup_mounts(config: &SandboxConfig) -> Result<()> {
    use std::ffi::CString;

    let root = config.workdir.join("root");
    std::fs::create_dir_all(root.join("tmp"))?;
    std::fs::create_dir_all(root.join("oldroot"))?;

    // Don't propagate our mounts to the host.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        bail!("make-rprivate failed");
    }

    // Allowlist files reach the guest exclusively via guest.tar (read-only
    // TarRo layer). No bind mounts: see NOTE above.

    // tmpfs on /tmp (writable scratch).
    let tmp_dst = root.join("tmp");
    let tmp_c = CString::new(tmp_dst.to_string_lossy().as_bytes())?;
    let rc = unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            tmp_c.as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            c"size=64m,mode=1777".as_ptr() as *const _,
        )
    };
    if rc != 0 {
        bail!("tmpfs on /tmp failed");
    }

    // pivot_root requires new_root to be a mountpoint: bind-mount it onto itself.
    {
        let root_c = CString::new(root.to_string_lossy().as_bytes())?;
        let rc = unsafe {
            libc::mount(
                root_c.as_ptr(),
                root_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            bail!("self bind-mount of new root failed");
        }
    }

    // pivot_root into the new root.
    let root_c = CString::new(root.to_string_lossy().as_bytes())?;
    let old_c = CString::new(root.join("oldroot").to_string_lossy().as_bytes())?;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            root_c.as_ptr(),
            old_c.as_ptr(),
        )
    };
    if rc != 0 {
        bail!("pivot_root failed");
    }
    unsafe {
        libc::chdir(c"/".as_ptr());
        // Detach the old root.
        let rc = libc::umount2(c"/oldroot".as_ptr(), libc::MNT_DETACH);
        if rc != 0 {
            bail!("umount oldroot failed");
        }
        libc::rmdir(c"/oldroot".as_ptr());
    }
    Ok(())
}

/// RLIMIT_AS + RLIMIT_CPU + RLIMIT_NPROC (cgroup v2 not writable here;
/// documented fallback). NPROC bounds tasks for the child's real UID
/// (nobody/65534 on the host), so a fork bomb cannot exhaust host PIDs even
/// if the seccomp clone policy were bypassed.
fn apply_rlimits(manifest: &Manifest) -> Result<()> {
    let mem = libc::rlimit {
        rlim_cur: manifest.memory_limit,
        rlim_max: manifest.memory_limit,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &mem) } != 0 {
        bail!("setrlimit AS failed");
    }
    let cpu = libc::rlimit {
        rlim_cur: manifest.cpu_limit,
        rlim_max: manifest.cpu_limit,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CPU, &cpu) } != 0 {
        bail!("setrlimit CPU failed");
    }
    let nproc = libc::rlimit {
        rlim_cur: manifest.max_processes,
        rlim_max: manifest.max_processes,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &nproc) } != 0 {
        bail!("setrlimit NPROC failed");
    }
    Ok(())
}

/// Drop all capabilities (bounding + ambient).
fn drop_capabilities() -> Result<()> {
    // capset with empty sets.
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = CapHeader {
        version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,              // self
    };
    let data = [
        CapData { effective: 0, permitted: 0, inheritable: 0 },
        CapData { effective: 0, permitted: 0, inheritable: 0 },
    ];
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const _,
            data.as_ptr() as *const _,
        )
    };
    if rc != 0 {
        bail!("capset failed");
    }
    // Drop bounding set too.
    for cap in 0..64 {
        unsafe {
            libc::prctl(libc::PR_CAPBSET_DROP, cap as u64, 0, 0, 0);
        }
    }
    Ok(())
}

/// Outer seccomp-BPF: deny-by-default, kill on violation. This is the
/// kernel-enforced boundary that closes the rewriter-bypass hole (R2):
/// a JIT'd `syscall` instruction becomes a REAL host syscall, and the
/// kernel kills the process.
///
/// Task creation: clone/clone3 are DENIED unless the manifest explicitly
/// sets allow_clone (governor-authorized, signature-bound). A PID namespace
/// limits visibility, not host resources — so the default is denial, and
/// RLIMIT_NPROC (set in apply_rlimits) bounds tasks even when cloning is
/// allowed. Namespace-creating clone flags need no seccomp arg-check: the
/// child holds zero capabilities, so the kernel refuses them with EPERM.
pub fn apply_seccomp_filter(allow_clone: bool) -> Result<()> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
        SeccompFilter, SeccompRule,
    };

    // Mirrors the LiteBox platform's proven allowlist, plus `openat`
    // (RDONLY) for Rust std. Everything else -> KillProcess.
    let mut rules: Vec<(i64, Vec<SeccompRule>)> = vec![
        (libc::SYS_read, vec![]),
        (libc::SYS_write, vec![]),
        (libc::SYS_poll, vec![]),
        (libc::SYS_mmap, vec![]),
        (libc::SYS_mprotect, vec![]),
        (libc::SYS_munmap, vec![]),
        (libc::SYS_mremap, vec![]),
        (libc::SYS_rt_sigreturn, vec![]),
        (libc::SYS_sigaltstack, vec![]),
        (libc::SYS_tgkill, vec![]),
        (libc::SYS_timer_create, vec![]),
        (libc::SYS_timer_settime, vec![]),
        (libc::SYS_timer_delete, vec![]),
        (libc::SYS_rt_sigaction, vec![]),
        (libc::SYS_rt_sigprocmask, vec![]),
        (libc::SYS_exit, vec![]),
        (libc::SYS_exit_group, vec![]),
        (libc::SYS_futex, vec![]),
        (libc::SYS_getrandom, vec![]),
        (libc::SYS_rseq, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_get_robust_list, vec![]),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_gettid, vec![]),
        (libc::SYS_madvise, vec![]),
        (libc::SYS_brk, vec![]),
        (libc::SYS_getpid, vec![]),
        // open/openat: read-only only (arg-checked). The mount namespace
        // is the actual access control; this just reduces syscall surface.
        (
            libc::SYS_open,
            vec![SeccompRule::new(vec![SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::O_RDONLY as u64,
            )
            .unwrap()])
            .unwrap()],
        ),
        (
            libc::SYS_openat,
            vec![SeccompRule::new(vec![SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::O_RDONLY as u64,
            )
            .unwrap()])
            .unwrap()],
        ),
        (libc::SYS_close, vec![]),
        // Needed for the child to read its own maps / do basic introspection.
        (libc::SYS_newfstatat, vec![]),
        (libc::SYS_fstat, vec![]),
        // prctl: needed by seccompiler::apply_filter_all_threads (the inner
        // LiteBox filter uses TSYNC). Safe: seccomp filters can only be made
        // more restrictive, never removed; namespaces/caps already confine.
        (libc::SYS_prctl, vec![]),
        // seccomp: the inner LiteBox filter installs itself via the seccomp
        // syscall. Safe: can only ADD filters (more restrictive), never remove.
        (libc::SYS_seccomp, vec![]),
    ];
    if allow_clone {
        // Governor-authorized threaded guests: cloning permitted, still
        // bounded by RLIMIT_NPROC. Namespace-creating flags are refused by
        // the kernel (zero capabilities -> EPERM), so no arg checks needed.
        rules.push((libc::SYS_clone, vec![]));
        rules.push((libc::SYS_clone3, vec![]));
    }
    // Note: clone/clone3 are ABSENT by default -> KillProcess. A PID
    // namespace limits visibility, not host resources; denial is the quota.
    let rule_map: std::collections::BTreeMap<i64, Vec<SeccompRule>> =
        rules.into_iter().collect();
    let filter = SeccompFilter::new(
        rule_map,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        seccompiler::TargetArch::x86_64,
    )
    .context("building seccomp filter")?;
    let bpf_prog: BpfProgram = filter.try_into().context("compiling BPF")?;
    seccompiler::apply_filter(&bpf_prog).context("applying seccomp filter")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P1 regression (isolated-filter scope): a process under the default
    /// filter that attempts clone must die by SIGSYS — the kernel kills it,
    /// no userspace policy involved.
    #[test]
    fn clone_denied_by_default_filter() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: install the default (allow_clone=false) filter, then
            // attempt the forbidden syscall. Must not return.
            apply_seccomp_filter(false).expect("filter install failed");
            let rc = unsafe { libc::syscall(libc::SYS_clone, 0u64, 0u64, 0u64, 0u64, 0u64) };
            // If we get here the filter did NOT kill us: fail loudly.
            unsafe { libc::_exit(100 + (rc < 0) as i32) };
        }
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(rc, pid);
        // WIFSIGNALED && WTERMSIG == SIGSYS (31)
        assert!(
            (status & 0x7f) != 0 && (status & 0x7f) != 0x7f,
            "child was not killed by a signal (status={status:#x})"
        );
        assert_eq!(
            status & 0x7f,
            libc::SIGSYS,
            "child died by signal {}, expected SIGSYS",
            status & 0x7f
        );
    }

    /// allow_clone=true keeps clone usable (governor-authorized threaded
    /// guests); the RLIMIT_NPROC quota is the bound there (tested full-stack).
    #[test]
    fn clone_allowed_when_authorized() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            apply_seccomp_filter(true).expect("filter install failed");
            // fork() via libc uses clone; must succeed and the child exits.
            let c = unsafe { libc::fork() };
            if c == 0 {
                unsafe { libc::_exit(42) };
            }
            assert!(c > 0, "clone denied despite allow_clone=true");
            let mut st = 0;
            unsafe { libc::waitpid(c, &mut st, 0) };
            let code = (st >> 8) & 0xff;
            unsafe { libc::_exit(if code == 42 { 0 } else { 101 }) };
        }
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(rc, pid);
        assert_eq!((status >> 8) & 0xff, 0, "allow_clone path failed");
    }
}

/// Close every file descriptor except 0, 1, 2 and those in `preserve`.
/// The upper bound comes from RLIMIT_NOFILE so no inherited fd survives,
/// however high-numbered.
fn sanitize_fds(preserve: &[RawFd]) {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let max_fd = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
        rl.rlim_cur.min(1 << 20) as i32
    } else {
        1024
    };
    for fd in 3..max_fd {
        if preserve.contains(&fd) {
            continue;
        }
        unsafe {
            libc::close(fd);
        }
    }
}

/// Measure what the child actually built. Called after apply_rlimits, before
/// setup_mounts (needs /proc and the pre-pivot filesystem for some probes).
fn measure_setup() -> Result<SetupReport> {
    // PID namespace: we must be PID 1 in the new namespace.
    let pid_is_one = unsafe { libc::getpid() } == 1;

    // Net namespace: list interfaces (fresh net ns has only lo, if that).
    let mut net_ifaces = Vec::new();
    unsafe {
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut addrs) == 0 {
            let mut cur = addrs;
            while !cur.is_null() {
                let name = std::ffi::CStr::from_ptr((*cur).ifa_name);
                let s = name.to_string_lossy().into_owned();
                if !net_ifaces.contains(&s) {
                    net_ifaces.push(s);
                }
                cur = (*cur).ifa_next;
            }
            libc::freeifaddrs(addrs);
        }
    }

    // Rlimits: read back what apply_rlimits set.
    let get = |res: libc::__rlimit_resource_t| -> Result<u64> {
        let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if unsafe { libc::getrlimit(res, &mut rl) } != 0 {
            bail!("getrlimit failed");
        }
        Ok(rl.rlim_cur)
    };
    let rlimit_as = get(libc::RLIMIT_AS)?;
    let rlimit_cpu = get(libc::RLIMIT_CPU)?;
    let rlimit_nproc = get(libc::RLIMIT_NPROC)?;

    // Pre-drop CapEff from /proc/self/status (gone after pivot_root).
    let pre_drop_cap_eff = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .unwrap_or("CapEff:\t?")
        .to_string();

    // Landlock availability probe.
    let landlock_available = std::path::Path::new("/sys/kernel/security").exists();

    Ok(SetupReport {
        pid_is_one,
        net_ifaces,
        rlimit_as,
        rlimit_cpu,
        rlimit_nproc,
        pre_drop_cap_eff,
        cap_eff_zero_after_drop: false, // filled after drop_capabilities
        landlock_available,
    })
}

/// True if the effective capability set is empty (post-drop measurement).
fn cap_eff_is_zero() -> Result<bool> {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = CapHeader {
        version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let mut data = [
        CapData { effective: 0, permitted: 0, inheritable: 0 },
        CapData { effective: 0, permitted: 0, inheritable: 0 },
    ];
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &header as *const _,
            data.as_mut_ptr() as *mut _,
        )
    };
    if rc != 0 {
        bail!("capget failed");
    }
    Ok(data.iter().all(|d| d.effective == 0))
}
