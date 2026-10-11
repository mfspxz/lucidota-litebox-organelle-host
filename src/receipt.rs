//! PL-style receipt for an organelle execution.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What the outer sandbox enforced (all booleans are measured, not assumed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterSandbox {
    pub user_ns: bool,
    pub mount_ns: bool,
    pub pid_ns: bool,
    pub net_ns: bool,
    /// "deny-by-default (kill_process)" or "unavailable: <reason>"
    pub seccomp: String,
    /// "enforcing" or "unavailable: <reason>"
    pub landlock: String,
    /// "cgroup v2" or "rlimit fallback: <reason>"
    pub resource_limits: String,
    pub capabilities_dropped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub wall_ms: u64,
    pub user_ms: u64,
    pub sys_ms: u64,
    pub max_rss_kb: u64,
}

/// PL-style receipt. Every claim in here must be backed by an observation
/// made during this run — see threat-model.md for what is NOT claimed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub organelle_id: String,
    pub authority: String,
    /// "verified" (signature checked against --trusted-key) or
    /// "unverified-local" (no key; authority is a caller claim).
    pub auth_status: String,
    /// Grant's invocation id (replay binding), or "none".
    pub invocation_id: String,
    pub sandbox: String,   // "litebox"
    pub platform: String,  // "linux_userland"
    pub outer_sandbox: OuterSandbox,
    /// Distinct guest syscall names observed OK (from shim telemetry).
    pub syscalls_allowed: Vec<String>,
    /// Distinct guest syscall names observed denied (shim Err).
    pub syscalls_denied: Vec<String>,
    /// Raw counts (may include repeats).
    pub syscall_total: u64,
    /// Distinct guest paths opened read-only and successfully.
    pub files_read: Vec<String>,
    /// Distinct guest paths opened for write and successfully.
    pub files_written: Vec<String>,
    /// "exit(<code>)" | "signal(<name>)" | "timeout"
    pub exit_status: String,
    pub timed_out: bool,
    pub resource_usage: ResourceUsage,
    /// sha256 of captured guest stdout (retained prefix; see truncation fields).
    pub artifact_hash: String,
    /// Guest stdout accounting (parent-side bounded drain).
    pub stdout_stored_bytes: u64,
    pub stdout_observed_bytes: u64,
    pub stdout_truncated: bool,
    /// Guest stderr accounting (parent-side bounded drain).
    pub stderr_stored_bytes: u64,
    pub stderr_observed_bytes: u64,
    pub stderr_truncated: bool,
    /// sha256 of canonical manifest JSON.
    pub policy_hash: String,
    /// sha256 of the guest tar (what actually ran).
    pub tar_hash: String,
    pub network: String, // "deny (no TUN, net ns has zero interfaces)"
    /// Honest notes: what was NOT proven, what was skipped and why.
    pub caveats: Vec<String>,
}

impl Receipt {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Stable digest of the receipt minus timing fields (for chaining).
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut m = BTreeMap::new();
        m.insert("organelle_id", self.organelle_id.clone());
        m.insert("exit_status", self.exit_status.clone());
        m.insert("artifact_hash", self.artifact_hash.clone());
        m.insert("policy_hash", self.policy_hash.clone());
        m.insert("tar_hash", self.tar_hash.clone());
        let j = serde_json::to_string(&m).unwrap();
        hex(&Sha256::digest(j.as_bytes()))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
