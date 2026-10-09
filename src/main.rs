//! litebox-organelle-host: hardened organelle execution.
//!
//! Usage: litebox-organelle-host run --manifest <manifest.json>
//!
//! The parent parses the manifest, builds the guest tar, clones a sandboxed
//! child (namespaces + seccomp), enforces a watchdog timeout, and emits a
//! PL-style receipt JSON on stdout.

mod guest;
mod manifest;
mod receipt;
mod sandbox;
mod syscalls;
mod tarball;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::os::fd::RawFd;
use std::time::Duration;

use manifest::Manifest;
use receipt::{Receipt, ResourceUsage};

fn main() {
    if let Err(e) = real_main() {
        eprintln!("fatal: {e:?}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 || args[1] != "run" || args[2] != "--manifest" {
        bail!("usage: {} run --manifest <manifest.json>", args[0]);
    }
    let manifest_json = std::fs::read_to_string(&args[3]).context("read manifest")?;
    let manifest = Manifest::parse(&manifest_json)?;

    // Canonical policy hash (what the governor authorized).
    let policy_hash = hex(&Sha256::digest(manifest.canonical_json()?.as_bytes()));

    // Build the guest tar (program rewritten + libs + allowlist).
    let (tar_data, tar_hash) =
        tarball::build_guest_tar(&manifest.command[0], &manifest.filesystem_allowlist)?;

    // Workdir for this run.
    let workdir = std::env::temp_dir().join(format!(
        "organelle-{}-{}",
        sanitize(&manifest.organelle_id),
        std::process::id()
    ));
    std::fs::create_dir_all(&workdir)?;
    std::fs::write(workdir.join("guest.tar"), &tar_data)?;
    std::fs::write(workdir.join("manifest.json"), &manifest_json)?;
    let error_path = workdir.join("setup_error.txt");

    // Pipes: child's stdout/stderr (guest output), and the uid_map sync pipe.
    let (stdout_r, stdout_w) = make_pipe()?;
    let (stderr_r, stderr_w) = make_pipe()?;
    let (sync_r, sync_w) = make_pipe()?;

    let config = sandbox::SandboxConfig {
        workdir: workdir.clone(),
        manifest: manifest.clone(),
        program: manifest.command[0].clone(),
        argv: manifest.command.clone(),
        stdout_w,
        stderr_w,
        sync_r,
        sync_w,
        error_path: error_path.clone(),
    };

    // Clone the sandboxed child.
    let (_pending, child_pid) = sandbox::run_sandboxed(config)?;

    // Drain stdout/stderr concurrently (avoid pipe-buffer deadlock).
    let out_handle = std::thread::spawn(move || read_all(stdout_r));
    let err_handle = std::thread::spawn(move || read_all(stderr_r));

    // Watchdog.
    let timeout = Duration::from_secs(manifest.timeout_secs);
    let mut result = sandbox::wait_with_timeout(child_pid, timeout)?;
    result.rusage.wall_ms = result.wall_ms;

    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();

    // Telemetry (written by the child after the guest exits).
    let telem_path = workdir.join("telemetry.json");
    let telem: serde_json::Value = std::fs::read_to_string(&telem_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({"syscalls": [], "files": []}));

    // Setup errors (if the child died before running the guest).
    let setup_error = std::fs::read_to_string(&error_path).ok().filter(|s| !s.is_empty());

    // Build the receipt.
    let (allowed, denied, total) = summarize_syscalls(&telem);
    let (files_read, files_written) = summarize_files(&telem);
    let artifact_hash = hex(&Sha256::digest(&stdout));

    let exit_status = if result.timed_out {
        "timeout".to_string()
    } else if let Some(code) = result.exit_code {
        if code == 127 && setup_error.is_some() {
            "child_setup_failed(127)".to_string()
        } else {
            format!("exit({code})")
        }
    } else if let Some(sig) = result.signal {
        format!("signal({})", signal_name(sig))
    } else {
        "unknown".to_string()
    };

    let mut caveats = vec![
        "landlock: kernel does not expose it; not enforced (outer seccomp + mount ns cover file access)".to_string(),
        "cgroup v2: not writable in this environment; RLIMIT_AS + RLIMIT_CPU used instead".to_string(),
        "syscall rewriter is best-effort (R2): the outer seccomp-BPF deny-by-default is the enforcement layer".to_string(),
        "does NOT defend against kernel exploits or microarchitectural side channels".to_string(),
    ];
    if let Some(e) = setup_error {
        caveats.push(format!("child setup error: {}", e.trim()));
    }
    if !stderr.is_empty() {
        caveats.push(format!(
            "guest stderr ({} bytes) not in artifact_hash; see logs",
            stderr.len()
        ));
    }

    let receipt = Receipt {
        organelle_id: manifest.organelle_id.clone(),
        authority: manifest.authority.clone(),
        sandbox: "litebox".to_string(),
        platform: "linux_userland".to_string(),
        outer_sandbox: sandbox::describe(),
        syscalls_allowed: allowed,
        syscalls_denied: denied,
        syscall_total: total,
        files_read,
        files_written,
        exit_status,
        timed_out: result.timed_out,
        resource_usage: ResourceUsage {
            wall_ms: result.rusage.wall_ms,
            user_ms: result.rusage.user_ms,
            sys_ms: result.rusage.sys_ms,
            max_rss_kb: result.rusage.max_rss_kb,
        },
        artifact_hash,
        policy_hash,
        tar_hash,
        network: "deny (no TUN device; net namespace has zero interfaces)".to_string(),
        caveats,
    };

    println!("{}", receipt.to_json());
    eprintln!("receipt digest: {}", receipt.digest());

    // Best-effort cleanup (keep the workdir on failure for forensics).
    let failed = result.timed_out || result.exit_code != Some(0);
    if !failed {
        let _ = std::fs::remove_dir_all(&workdir);
    } else {
        eprintln!("workdir kept for forensics: {}", workdir.display());
    }

    Ok(())
}

fn make_pipe() -> Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe failed");
    }
    Ok((fds[0], fds[1]))
}

fn read_all(fd: RawFd) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let rc = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if rc <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..rc as usize]);
    }
    unsafe { libc::close(fd) };
    out
}

fn summarize_syscalls(telem: &serde_json::Value) -> (Vec<String>, Vec<String>, u64) {
    let mut allowed = BTreeSet::new();
    let mut denied = BTreeSet::new();
    let mut total = 0u64;
    if let Some(arr) = telem.get("syscalls").and_then(|v| v.as_array()) {
        total = arr.len() as u64;
        for e in arr {
            let nr = e.get("nr").and_then(|v| v.as_u64()).unwrap_or(9999) as u32;
            let ok = e.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            let name = syscalls::name(nr).to_string();
            if ok {
                allowed.insert(name);
            } else {
                denied.insert(name);
            }
        }
    }
    (
        allowed.into_iter().collect(),
        denied.into_iter().collect(),
        total,
    )
}

fn summarize_files(telem: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let mut read = BTreeSet::new();
    let mut written = BTreeSet::new();
    if let Some(arr) = telem.get("files").and_then(|v| v.as_array()) {
        for e in arr {
            let path = e.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            let write = e.get("write").and_then(|v| v.as_bool()).unwrap_or(false);
            let ok = e.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            if !ok {
                continue;
            }
            if write {
                written.insert(path.to_string());
            } else {
                read.insert(path.to_string());
            }
        }
    }
    (read.into_iter().collect(), written.into_iter().collect())
}

fn signal_name(sig: i32) -> &'static str {
    match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        31 => "SIGSYS",
        _ => "UNKNOWN",
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(32)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
