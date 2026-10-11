//! Regression tests for the Phase 2 host fix (2026-10-10):
//! non-empty `filesystem_allowlist` must work via the read-only tar channel.
//!
//! Background: `setup_mounts` used to bind-mount allowlist entries read-only,
//! but the nobody-mapped child gets EPERM on the bind remount-ro (the
//! remount needs CAP_SYS_ADMIN in the userns owning the source superblock),
//! so every non-empty allowlist died as child_setup_failed(127). Phase 1
//! never exercised a non-empty allowlist (all 9 hostile probes used `[]`).
//! The fix: the guest tar (read-only TarRo layer) is the SOLE file-ingress
//! path; no bind mounts. These tests pin that behavior, including the
//! hostile shapes (symlink escape, unreadable file).
//!
//! REQUIREMENT: user namespaces must be available (unprivileged userns).
//! Each test shells out to the real host binary (CARGO_BIN_EXE) and runs a
//! real sandboxed guest; nothing is mocked.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn host_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_litebox-organelle-host"))
}

/// Unique scratch dir under the workspace (real disk; /tmp may be a tiny tmpfs).
fn scratch(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("allowlist-test")
        .join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_manifest(dir: &std::path::Path, command: &[&str], allowlist: &[String]) -> PathBuf {
    let m = serde_json::json!({
        "organelle_id": "allowlist-regression",
        "authority": "hostfix-test",
        "command": command,
        "filesystem_allowlist": allowlist,
        "network": "deny",
        "cpu_limit": 30,
        "memory_limit": 268435456,
        "timeout_secs": 60,
        "stdout_limit_bytes": 16777216,
        "stderr_limit_bytes": 16777216,
        "max_processes": 64,
    });
    let p = dir.join("manifest.json");
    std::fs::write(&p, serde_json::to_string(&m).unwrap()).unwrap();
    p
}

/// Run the host binary; returns (exit_code, stdout, stderr).
fn run_host(manifest: &std::path::Path, workdir: &std::path::Path) -> (i32, String, String) {
    let out = Command::new(host_bin())
        .arg("run")
        .arg("--manifest")
        .arg(manifest)
        .env("TMPDIR", workdir)
        .output()
        .expect("spawn host binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Extract the receipt JSON from the host's stdout (stdout is the pure
/// receipt JSON; the `receipt digest:` trailer goes to stderr).
fn parse_receipt(stdout: &str) -> Value {
    serde_json::from_str(stdout.trim()).expect("receipt parses")
}

/// The exact hole Phase 1 missed: a NON-EMPTY allowlist, end to end.
/// Guest (/bin/cat) reads an allowlisted input file; its stdout must be
/// exactly the file bytes, and artifact_hash must be their sha256.
#[test]
fn guest_reads_allowlisted_file_end_to_end() {
    let dir = scratch("e2e");
    let input = dir.join("input.txt");
    let content = b"ALLOWLIST-CONTENT-42\n";
    std::fs::write(&input, content).unwrap();

    let manifest = write_manifest(
        &dir,
        &["/bin/cat", input.to_str().unwrap()],
        &[dir.to_str().unwrap().to_string()],
    );
    let (code, stdout, stderr) = run_host(&manifest, &dir);
    assert_eq!(code, 0, "host exit code; stderr: {stderr}");

    let r = parse_receipt(&stdout);
    assert_eq!(r["exit_status"], "exit(0)", "guest exit status");
    assert_eq!(r["stdout_observed_bytes"], content.len() as u64);

    // artifact_hash is sha256 over the guest's stdout bytes.
    use sha2::{Digest, Sha256};
    let expected: String = Sha256::digest(content).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(r["artifact_hash"], expected, "output hash binds file bytes");

    // The guest saw the file read-only via the tar: no bind mounts exist
    // anymore, and the tar entry has write bits cleared (asserted here by
    // re-reading the built tar out of the kept workdir is overkill; the
    // read-only property is covered by tarball unit semantics).
}

/// Hostile: an allowlist entry that is a symlink pointing outside must be
/// REFUSED, fail closed — even when the target itself is world-readable, so
/// only the symlink check can be responsible for the refusal.
#[test]
fn allowlist_symlink_pointing_outside_is_refused() {
    let dir = scratch("symlink");
    // Readable target: the refusal must come from the symlink rule, not from
    // an unreadable target.
    let link = dir.join("evil-link");
    std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();

    let manifest = write_manifest(
        &dir,
        &["/bin/cat", "/does/not/matter"],
        &[link.to_str().unwrap().to_string()],
    );
    let (code, _stdout, stderr) = run_host(&manifest, &dir);
    assert_eq!(code, 1, "host must refuse the manifest (exit 1)");
    assert!(
        !stderr.contains("receipt digest:"),
        "no receipt: the guest must never run"
    );
}

/// Hostile: an allowlist entry the operator cannot read (e.g. /etc/shadow
/// for a non-root operator) must be REFUSED, fail closed — never silently
/// omitted, never visible to the guest.
#[test]
fn allowlist_unreadable_file_is_refused() {
    // As root every file is readable, so the refusal cannot trigger; the
    // symlink test above covers the hostile shape for root. Skip honestly.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("SKIP: running as root; unreadable-file refusal not triggerable");
        return;
    }
    let dir = scratch("shadow");
    let manifest = write_manifest(
        &dir,
        &["/bin/cat", "/does/not/matter"],
        &["/etc/shadow".to_string()],
    );
    let (code, _stdout, stderr) = run_host(&manifest, &dir);
    assert_eq!(code, 1, "host must refuse unreadable allowlist entry; stderr: {stderr}");
    assert!(
        !stderr.contains("receipt digest:"),
        "no receipt: the guest must never run"
    );
}
