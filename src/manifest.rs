//! Organelle manifest: what the governor authorizes the sandbox to run.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The manifest is the governor's authorization. The host enforces it;
/// anything not in the manifest is denied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub organelle_id: String,
    pub authority: String,
    /// argv[0] must be an absolute guest path (e.g. "/bin/echo").
    pub command: Vec<String>,
    /// Host paths to make visible inside the sandbox (read-only), plus the
    /// program's own ELF dependencies (resolved automatically).
    pub filesystem_allowlist: Vec<String>,
    /// Pilot only supports "deny".
    pub network: String,
    /// CPU seconds (RLIMIT_CPU).
    pub cpu_limit: u64,
    /// Bytes (RLIMIT_AS).
    pub memory_limit: u64,
    /// Wall-clock seconds; the watchdog SIGKILLs on expiry.
    pub timeout_secs: u64,
    /// Max guest stdout bytes retained (parent-side). Default 16 MiB.
    #[serde(default = "default_output_limit")]
    pub stdout_limit_bytes: u64,
    /// Max guest stderr bytes retained (parent-side). Default 16 MiB.
    #[serde(default = "default_output_limit")]
    pub stderr_limit_bytes: u64,
    /// RLIMIT_NPROC: max tasks (processes + threads) for the child.
    /// Defense-in-depth under the seccomp clone policy.
    #[serde(default = "default_max_processes")]
    pub max_processes: u64,
    /// If true, the seccomp filter allows clone/clone3 (still bounded by
    /// max_processes). Default false: task creation is denied outright.
    /// Intended to be governor-authorized (signature-bound) for threaded
    /// guests; a caller-supplied true without a verified signature is
    /// rejected when --trusted-key is in effect (see auth).
    #[serde(default)]
    pub allow_clone: bool,
    /// Keep the run workdir (guest stdout/stderr dumps, tar, telemetry)
    /// after the run for forensics/evidence. Default false (cleaned on
    /// success, kept on failure).
    #[serde(default)]
    pub keep_workdir: bool,
}

fn default_output_limit() -> u64 {
    16 * 1024 * 1024
}

fn default_max_processes() -> u64 {
    64
}

impl Manifest {
    pub fn parse(json: &str) -> Result<Self> {
        let m: Manifest =
            serde_json::from_str(json).context("manifest is not valid JSON")?;
        m.validate()?;
        Ok(m)
    }

    fn validate(&self) -> Result<()> {
        if self.organelle_id.is_empty() {
            bail!("organelle_id must not be empty");
        }
        if self.command.is_empty() {
            bail!("command must not be empty");
        }
        if !self.command[0].starts_with('/') {
            bail!("command[0] must be an absolute guest path");
        }
        if self.network != "deny" {
            bail!("pilot only supports network: \"deny\"");
        }
        if self.timeout_secs == 0 || self.timeout_secs > 3600 {
            bail!("timeout_secs must be in 1..=3600");
        }
        if self.memory_limit < 16 * 1024 * 1024 {
            bail!("memory_limit must be >= 16MiB");
        }
        if self.stdout_limit_bytes < 64 * 1024 || self.stdout_limit_bytes > 1024 * 1024 * 1024
        {
            bail!("stdout_limit_bytes must be in 64KiB..=1GiB");
        }
        if self.stderr_limit_bytes < 64 * 1024 || self.stderr_limit_bytes > 1024 * 1024 * 1024
        {
            bail!("stderr_limit_bytes must be in 64KiB..=1GiB");
        }
        if self.max_processes == 0 || self.max_processes > 4096 {
            bail!("max_processes must be in 1..=4096");
        }
        for p in &self.filesystem_allowlist {
            let pb = PathBuf::from(p);
            if !pb.is_absolute() {
                bail!("allowlist entry must be absolute: {p}");
            }
            if !pb.exists() {
                bail!("allowlist entry does not exist on host: {p}");
            }
        }
        // The program itself must be resolvable on the host (we rewrite + pack it).
        let prog = PathBuf::from(&self.command[0]);
        if !prog.exists() {
            bail!("program not found on host: {}", self.command[0]);
        }
        Ok(())
    }

    /// Canonical JSON for policy_hash (sorted keys, no whitespace).
    pub fn canonical_json(&self) -> Result<String> {
        let v = serde_json::to_value(self)?;
        Ok(canonical(&v))
    }
}

fn canonical(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(&m[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(a) => {
            let parts: Vec<String> = a.iter().map(canonical).collect();
            format!("[{}]", parts.join(","))
        }
        _ => serde_json::to_string(v).unwrap(),
    }
}
