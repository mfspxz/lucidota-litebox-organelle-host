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
    // Usage: run --manifest <manifest.json> [--trusted-key <hex-ed25519-pub>]
    if args.len() < 4 || args.len() > 6 || args[1] != "run" || args[2] != "--manifest" {
        bail!(
            "usage: {} run --manifest <manifest.json> [--trusted-key <hex>]",
            args[0]
        );
    }
    let mut trusted_key: Option<&str> = None;
    if args.len() == 6 {
        if args[4] != "--trusted-key" {
            bail!(
                "usage: {} run --manifest <manifest.json> [--trusted-key <hex>]",
                args[0]
            );
        }
        trusted_key = Some(&args[5]);
    }
    let manifest_json = std::fs::read_to_string(&args[3]).context("read manifest")?;
    let manifest = Manifest::parse(&manifest_json)?;

    // Authenticate BEFORE doing anything with the manifest's contents.
    // Strict mode (--trusted-key): ungrants are rejected here, fail closed.
    let auth_outcome = manifest.authenticate(trusted_key)?;
    if auth_outcome.status == manifest::AuthStatus::UnverifiedLocal {
        eprintln!("warning: no --trusted-key; running in UNVERIFIED local mode");
    }

    // Bind the exact program bytes to the grant: if the signed manifest
    // names a program hash, the file must match before we package it.
    if let Some(expected) = &manifest.program_sha256 {
        let prog_bytes =
            std::fs::read(&manifest.command[0]).context("read program for hash check")?;
        let actual = hex(&Sha256::digest(&prog_bytes));
        if &actual != expected {
            bail!("program_sha256 mismatch: manifest names {expected}, file is {actual}");
        }
    }

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

    // Drain stdout/stderr concurrently (avoid pipe-buffer deadlock) through
    // BOUNDED drains: the guest's RLIMIT_AS does not constrain parent-side
    // allocations, so an unbounded Vec<u8> here is a host-memory exhaustion
    // vector. Output beyond the budget is dropped (hash covers what arrived
    // up to the budget; the receipt records truncation honestly).
    let stdout_path = workdir.join("stdout.bin");
    let stderr_path = workdir.join("stderr.bin");
    let out_budget = manifest.stdout_limit_bytes;
    let err_budget = manifest.stderr_limit_bytes;
    let out_handle =
        std::thread::spawn(move || drain_bounded(stdout_r, out_budget, &stdout_path));
    let err_handle =
        std::thread::spawn(move || drain_bounded(stderr_r, err_budget, &stderr_path));

    // Watchdog.
    let timeout = Duration::from_secs(manifest.timeout_secs);
    let mut result = sandbox::wait_with_timeout(child_pid, timeout)?;
    result.rusage.wall_ms = result.wall_ms;

    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();

    // Setup report (measured by the child before seccomp installed).
    // Missing/unparseable -> every claim becomes "not_measured", never zero.
    let setup: Option<sandbox::SetupReport> = std::fs::read_to_string(workdir.join("setup_report.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    // Shim telemetry: the pinned litebox_shim_linux exposes no telemetry
    // API. The parent synthesizes the explicit unavailable marker itself —
    // the old child-written telemetry.json is gone (writing it required
    // post-filter lseek/ftruncate, which are not allowlisted).
    let telem = serde_json::json!({
        "syscalls": [],
        "files": [],
        "unavailable": "litebox_shim_linux has no telemetry API",
    });

    // Setup errors (if the child died before running the guest). Lines
    // starting with "stage: " are progress markers, not errors.
    let setup_error = std::fs::read_to_string(&error_path)
        .ok()
        .map(|s| {
            s.lines()
                .filter(|l| !l.starts_with("stage:"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|s| !s.trim().is_empty());

    // Build the receipt.
    //
    // Telemetry honesty (fix 6): the pinned shim exposes no telemetry API,
    // so `telem` carries an explicit "unavailable" marker synthesized by the
    // parent. In that case every telemetry field is None — never an empty
    // vec or a zero count masquerading as "nothing happened".
    let telemetry_unavailable: Option<String> = telem
        .get("unavailable")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let telemetry_status = match &telemetry_unavailable {
        Some(reason) => format!("unavailable: {reason}"),
        None => "observed".to_string(),
    };
    let (syscalls_allowed, syscalls_denied, syscall_total) = match &telemetry_unavailable {
        Some(_) => (None, None, None),
        None => {
            let (a, d, t) = summarize_syscalls(&telem);
            (Some(a), Some(d), Some(t))
        }
    };
    let (files_read, files_written) = match &telemetry_unavailable {
        Some(_) => (None, None),
        None => {
            let (r, w) = summarize_files(&telem);
            (Some(r), Some(w))
        }
    };
    let artifact_hash = stdout.hash_hex.clone();

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
        "syscall rewriter is best-effort (R2): the outer seccomp-BPF deny-by-default is the enforcement layer".to_string(),
        "does NOT defend against kernel exploits or microarchitectural side channels".to_string(),
    ];
    // Measured sandbox description (fail-closed on missing evidence).
    // Network claim built from the measured interface list, not a slogan.
    let network = match &setup {
        Some(s) => format!(
            "deny (no TUN device; net namespace interfaces: {:?})",
            s.net_ifaces
        ),
        None => "deny (no TUN device; interfaces not_measured)".to_string(),
    };
    let (outer_sandbox, mut setup_caveats) = sandbox::describe_measured(setup);
    // Landlock honesty: the old hard-coded "kernel does not expose it" was
    // wrong on kernels that do — report what was measured.
    if outer_sandbox.landlock.starts_with("unavailable") {
        caveats.push(
            "landlock: unavailable on this host; not enforced (outer seccomp + mount ns cover file access)".to_string(),
        );
    }
    caveats.append(&mut setup_caveats);
    if let Some(reason) = &telemetry_unavailable {
        caveats.push(format!(
            "guest syscall/file telemetry unavailable: {reason}; telemetry fields are null, not zero"
        ));
    }
    if let Some(e) = setup_error {
        caveats.push(format!("child setup error: {}", e.trim()));
    }
    if auth_outcome.status == manifest::AuthStatus::UnverifiedLocal {
        caveats.push(
            "manifest NOT signature-verified (no --trusted-key): the authority string is a caller claim, not a grant".to_string(),
        );
    }
    if !stderr.is_empty() {
        caveats.push(format!(
            "guest stderr ({} bytes observed, {} retained) not in artifact_hash; see logs",
            stderr.observed_bytes, stderr.stored_bytes
        ));
    }
    if stdout.truncated {
        caveats.push(format!(
            "guest stdout truncated at {} byte budget ({} bytes observed); artifact_hash covers retained prefix only",
            manifest.stdout_limit_bytes, stdout.observed_bytes
        ));
    }
    if stderr.truncated {
        caveats.push(format!(
            "guest stderr truncated at {} byte budget ({} bytes observed)",
            manifest.stderr_limit_bytes, stderr.observed_bytes
        ));
    }

    let mut receipt = Receipt {
        receipt_version: receipt::RECEIPT_VERSION.to_string(),
        organelle_id: manifest.organelle_id.clone(),
        authority: auth_outcome.receipt_authority.clone(),
        auth_status: match auth_outcome.status {
            manifest::AuthStatus::Verified => "verified".to_string(),
            manifest::AuthStatus::UnverifiedLocal => "unverified-local".to_string(),
        },
        invocation_id: auth_outcome.invocation_id.clone(),
        sandbox: "litebox".to_string(),
        platform: "linux_userland".to_string(),
        outer_sandbox,
        telemetry_status,
        syscalls_allowed,
        syscalls_denied,
        syscall_total,
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
        stdout_stored_bytes: stdout.stored_bytes,
        stdout_observed_bytes: stdout.observed_bytes,
        stdout_truncated: stdout.truncated,
        stderr_stored_bytes: stderr.stored_bytes,
        stderr_observed_bytes: stderr.observed_bytes,
        stderr_truncated: stderr.truncated,
        policy_hash,
        tar_hash,
        network,
        caveats,
        receipt_digest: String::new(), // filled by seal()
    };
    // Seal: digest covers ALL fields (canonical JSON, sorted keys).
    receipt.seal();
    assert!(receipt.verify_digest(), "receipt digest self-check failed");

    // Append to the local proof ledger (hash-chained, append-only JSONL).
    // This is the persistence the digest binds to; the stderr digest line
    // is the independent witness.
    if let Err(e) = append_ledger(&receipt) {
        eprintln!("warning: ledger append failed: {e:?}");
    }

    println!("{}", receipt.to_json());
    eprintln!("receipt digest: {}", receipt.receipt_digest);

    // Best-effort cleanup (keep the workdir on failure, or whenever the
    // manifest asks for forensics).
    let failed = result.timed_out || result.exit_code != Some(0);
    if !failed && !manifest.keep_workdir {
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

/// Result of draining one guest output pipe through a byte budget.
#[derive(Default)]
struct Drain {
    /// sha256 hex of the retained prefix.
    hash_hex: String,
    /// Bytes written to the sink file (<= budget).
    stored_bytes: u64,
    /// Total bytes read from the pipe (may exceed budget).
    observed_bytes: u64,
    /// True if output exceeded the budget and was dropped.
    truncated: bool,
}

impl Drain {
    fn is_empty(&self) -> bool {
        self.observed_bytes == 0
    }
}

/// Drain `fd` into `sink_path`, retaining at most `budget` bytes.
/// The hash is incremental: parent memory stays O(1) regardless of how much
/// the guest emits. Surplus bytes are counted, not stored.
fn drain_bounded(fd: RawFd, budget: u64, sink_path: &std::path::Path) -> Drain {
    use sha2::Digest;
    use std::io::Write;
    let mut out = Drain::default();
    let mut hasher = Sha256::new();
    let mut file = std::fs::File::create(sink_path).ok();
    let mut buf = [0u8; 65536];
    loop {
        let rc = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if rc <= 0 {
            break;
        }
        let chunk = &buf[..rc as usize];
        out.observed_bytes += chunk.len() as u64;
        if out.stored_bytes < budget {
            let room = budget - out.stored_bytes;
            let take = chunk.len().min(room as usize);
            hasher.update(&chunk[..take]);
            if let Some(f) = file.as_mut() {
                let _ = f.write_all(&chunk[..take]);
            }
            out.stored_bytes += take as u64;
            if take < chunk.len() {
                out.truncated = true;
            }
        } else {
            out.truncated = true;
        }
    }
    unsafe { libc::close(fd) };
    out.hash_hex = hex(&hasher.finalize());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// P1 regression: the bounded drain caps retained bytes, keeps hashing,
    /// and reports truncation — parent memory stays O(1).
    #[test]
    fn drain_bounded_caps_and_hashes() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        // Write 3x the budget, then close the write end.
        let payload = vec![0xABu8; 3000];
        let mut written = 0;
        while written < payload.len() {
            let rc = unsafe {
                libc::write(
                    w,
                    payload[written..].as_ptr() as *const _,
                    payload.len() - written,
                )
            };
            assert!(rc > 0);
            written += rc as usize;
        }
        unsafe { libc::close(w) };
        let sink = std::env::temp_dir().join(format!("drain-test-{}", std::process::id()));
        let d = drain_bounded(r, 1000, &sink);
        assert_eq!(d.stored_bytes, 1000);
        assert_eq!(d.observed_bytes, 3000);
        assert!(d.truncated);
        assert_eq!(d.hash_hex, hex(&Sha256::digest(&payload[..1000])));
        assert_eq!(std::fs::read(&sink).unwrap().len(), 1000);
        let _ = std::fs::remove_file(&sink);
    }

    /// Under-budget output is retained fully and not marked truncated.
    #[test]
    fn drain_bounded_small_output_clean() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        let payload = b"hello";
        let rc = unsafe { libc::write(w, payload.as_ptr() as *const _, payload.len()) };
        assert_eq!(rc as usize, payload.len());
        unsafe { libc::close(w) };
        let sink = std::env::temp_dir().join(format!("drain-test2-{}", std::process::id()));
        let d = drain_bounded(r, 1000, &sink);
        assert_eq!(d.stored_bytes, 5);
        assert_eq!(d.observed_bytes, 5);
        assert!(!d.truncated);
        assert!(d.is_empty() == false);
        let _ = std::fs::remove_file(&sink);
    }
}

/// Append the sealed receipt to the local proof ledger
/// (~/workspace/litebox-organelle-host/receipts/ledger.jsonl).
/// Append-only JSONL; each entry hash-chains to the previous entry's
/// digest (tamper-evident). The stderr "receipt digest:" line is the
/// independent witness a verifier can check against this ledger.
fn append_ledger(receipt: &Receipt) -> Result<()> {
    let dir = std::path::PathBuf::from(env!("HOME"))
        .join("workspace/litebox-organelle-host/receipts");
    std::fs::create_dir_all(&dir).context("create receipts dir")?;
    let path = dir.join("ledger.jsonl");

    // Read the previous entry's digest for chaining (best-effort: a
    // missing/corrupt tail just starts a new chain segment, recorded).
    let prev: Option<String> = std::fs::read_to_string(&path).ok().and_then(|s| {
        s.lines()
            .rev()
            .find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .and_then(|v| v.get("digest").and_then(|d| d.as_str()).map(|d| d.to_string()))
    });

    let entry = serde_json::json!({
        "v": 1,
        "receipt_version": receipt.receipt_version,
        "digest": receipt.receipt_digest,
        "prev": prev,
        "invocation_id": receipt.invocation_id,
        "organelle_id": receipt.organelle_id,
        "exit_status": receipt.exit_status,
        "receipt": serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null),
    });
    let mut line = serde_json::to_string(&entry).context("serialize ledger entry")?;
    line.push('\n');

    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .context("open ledger")?;
    f.write_all(line.as_bytes()).context("append ledger")?;
    Ok(())
}
