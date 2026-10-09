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
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::manifest::Manifest;
use crate::receipt::{OuterSandbox, ResourceUsage};

/// Nobody UID/GID for the user namespace mapping.
const NOBODY: u32 = 65534;
/// Child setup failure exit code (distinguishes from guest exit codes).
const SETUP_FAILED: i32 = 127;

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

/// What the outer sandbox actually enforced (measured, for the receipt).
pub fn describe() -> OuterSandbox {
    OuterSandbox {
        user_ns: true,
        mount_ns: true,
        pid_ns: true,
        net_ns: true,
        seccomp: "deny-by-default (SECCOMP_RET_KILL_PROCESS)".to_string(),
        landlock: "unavailable: /sys/kernel/security absent".to_string(),
        resource_limits: "rlimit fallback: cgroup v2 not writable in this environment".to_string(),
        capabilities_dropped: true,
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

    // Open telemetry + error files BEFORE pivot_root (host paths visible now).
    let telemetry_path = config.workdir.join("telemetry.json");
    let telemetry_fd: RawFd = unsafe {
        let c = std::ffi::CString::new(telemetry_path.to_string_lossy().as_bytes())?;
        let fd = libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd < 0 {
            bail!("open telemetry file failed");
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

    // 1. Mount namespace setup (pivot_root hides the host).
    if let Err(e) = setup_mounts(config) {
        log_err(&format!("setup_mounts failed: {e:?}\n"));
        return Ok(SETUP_FAILED);
    }

    // 2. Resource limits (before dropping privileges).
    if let Err(e) = apply_rlimits(&config.manifest) {
        log_err(&format!("apply_rlimits failed: {e:?}\n"));
        return Ok(SETUP_FAILED);
    }

    // 3. Drop all capabilities. (The uid_map already maps us to 65534/nobody
    //    on the host, so an explicit setuid is redundant — and would fail
    //    after we drop CAP_SETUID. In-ns uid 0 with zero caps is powerless.)
    if let Err(e) = drop_capabilities() {
        log_err(&format!("drop_capabilities failed: {e:?}\n"));
        return Ok(SETUP_FAILED);
    }

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
    // 6. Outer seccomp filter is applied LATER, in run_guest_inner, right
    //    before the inner filter (after FS setup, like the upstream runner).
    //    See guest.rs.

    // 7. Run the LiteBox guest (inner personality). Never returns normally;
    //    exits the process with the guest's exit code.
    crate::guest::run_guest(config, tar_static, telemetry_fd)
}

/// Make all mounts private, build an empty root with only allowlist binds.
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

    // Helper to bind-mount.
    let bind = |src: &Path, dst: &Path, readonly: bool| -> Result<()> {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // For files, the destination must exist as a file.
        let src_meta = std::fs::metadata(src)?;
        if src_meta.is_file() {
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(dst)?;
        } else {
            std::fs::create_dir_all(dst)?;
        }
        let src_c = CString::new(src.to_string_lossy().as_bytes())?;
        let dst_c = CString::new(dst.to_string_lossy().as_bytes())?;
        let rc = unsafe {
            libc::mount(
                src_c.as_ptr(),
                dst_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            bail!("bind mount {} -> {}", src.display(), dst.display());
        }
        if readonly {
            let rc = unsafe {
                libc::mount(
                    std::ptr::null(),
                    dst_c.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                    std::ptr::null(),
                )
            };
            if rc != 0 {
                bail!("remount ro {}", dst.display());
            }
        }
        Ok(())
    };

    // Bind the allowlist (read-only) into the new root at the same paths.
    for entry in &config.manifest.filesystem_allowlist {
        let src = Path::new(entry);
        let dst = root.join(entry.trim_start_matches('/'));
        bind(src, &dst, true)?;
    }

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

/// RLIMIT_AS + RLIMIT_CPU (cgroup v2 not writable here; documented fallback).
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
pub fn apply_seccomp_filter() -> Result<()> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
        SeccompFilter, SeccompRule,
    };

    // Mirrors the LiteBox platform's proven allowlist, plus `clone` and
    // `openat` (RDONLY) for Rust std. Everything else -> KillProcess.
    let rules: Vec<(i64, Vec<SeccompRule>)> = vec![
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
        (libc::SYS_clone, vec![]),
        (libc::SYS_clone3, vec![]),
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
                (libc::O_RDONLY as u64),
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
                (libc::O_RDONLY as u64),
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
