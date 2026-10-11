//! PL-style receipt for an organelle execution.

use serde::{Deserialize, Serialize};

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
///
/// Format version: "litebox-receipt/1". The digest() covers the canonical
/// JSON (sorted keys) of EVERY field except receipt_digest itself — no
/// material claim is excluded from the hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Format version. Bump on any schema change; verifiers reject unknown.
    pub receipt_version: String,
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
    /// Telemetry status: "observed" or "unavailable: <reason>".
    /// When unavailable, ALL the fields below are None (null in JSON) —
    /// never empty vecs or zero counts. Absence of evidence is not
    /// evidence of absence.
    pub telemetry_status: String,
    /// Distinct guest syscall names observed OK (from shim telemetry).
    /// None = telemetry unavailable.
    pub syscalls_allowed: Option<Vec<String>>,
    /// Distinct guest syscall names observed denied (shim Err).
    /// None = telemetry unavailable.
    pub syscalls_denied: Option<Vec<String>>,
    /// Raw counts (may include repeats). None = telemetry unavailable.
    pub syscall_total: Option<u64>,
    /// Distinct guest paths opened read-only and successfully.
    /// None = telemetry unavailable.
    pub files_read: Option<Vec<String>>,
    /// Distinct guest paths opened for write and successfully.
    /// None = telemetry unavailable.
    pub files_written: Option<Vec<String>>,
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
    /// Hex SHA-256 over the canonical JSON of every other field (set by
    /// the host after construction; see digest()). Binds the receipt to the
    /// exact policy (policy_hash), program (tar_hash), invocation
    /// (invocation_id), and all sandbox/telemetry/resource claims.
    pub receipt_digest: String,
}

pub const RECEIPT_VERSION: &str = "litebox-receipt/1";

impl Receipt {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Canonical JSON: sorted keys, no whitespace. Used for the digest.
    pub fn canonical_json(&self) -> String {
        let v = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        canonical_value(&v)
    }

    /// Stable digest over ALL security-relevant fields (everything except
    /// receipt_digest itself). Binds invocation_id + exact policy
    /// (policy_hash) + program (tar_hash) + sandbox/telemetry/caveats.
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        // Blank the digest field, canonicalize, hash.
        let mut clone = self.clone();
        clone.receipt_digest = String::new();
        let canon = clone.canonical_json();
        hex(&Sha256::digest(canon.as_bytes()))
    }

    /// Fill receipt_digest from digest(). Call once, after construction.
    pub fn seal(&mut self) {
        self.receipt_digest = self.digest();
    }

    /// Verify a sealed receipt: recompute and compare.
    pub fn verify_digest(&self) -> bool {
        self.receipt_digest == self.digest()
    }
}

/// Canonical JSON with sorted object keys (recursive).
fn canonical_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap(),
        serde_json::Value::Array(a) => {
            let parts: Vec<String> = a.iter().map(canonical_value).collect();
            format!("[{}]", parts.join(","))
        }
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical_value(&m[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_receipt() -> Receipt {
        Receipt {
            receipt_version: RECEIPT_VERSION.to_string(),
            organelle_id: "test".to_string(),
            authority: "unverified-local:test".to_string(),
            auth_status: "unverified-local".to_string(),
            invocation_id: "none".to_string(),
            sandbox: "litebox".to_string(),
            platform: "linux_userland".to_string(),
            outer_sandbox: OuterSandbox {
                user_ns: false,
                mount_ns: false,
                pid_ns: false,
                net_ns: false,
                seccomp: "not_measured".to_string(),
                landlock: "not_measured".to_string(),
                resource_limits: "not_measured".to_string(),
                capabilities_dropped: false,
            },
            telemetry_status: "unavailable: test".to_string(),
            syscalls_allowed: None,
            syscalls_denied: None,
            syscall_total: None,
            files_read: None,
            files_written: None,
            exit_status: "exit(0)".to_string(),
            timed_out: false,
            resource_usage: ResourceUsage {
                wall_ms: 1,
                user_ms: 0,
                sys_ms: 0,
                max_rss_kb: 0,
            },
            artifact_hash: "aa".to_string(),
            stdout_stored_bytes: 0,
            stdout_observed_bytes: 0,
            stdout_truncated: false,
            stderr_stored_bytes: 0,
            stderr_observed_bytes: 0,
            stderr_truncated: false,
            policy_hash: "bb".to_string(),
            tar_hash: "cc".to_string(),
            network: "deny".to_string(),
            caveats: vec!["test caveat".to_string()],
            receipt_digest: String::new(),
        }
    }

    #[test]
    fn digest_covers_all_fields() {
        // Tampering with ANY field (including caveats, authority,
        // telemetry status) must break verification.
        let mut r = dummy_receipt();
        r.seal();
        assert!(r.verify_digest());
        for mutate in [
            |r: &mut Receipt| r.authority = "verified:evil".to_string(),
            |r: &mut Receipt| r.caveats.push("hidden".to_string()),
            |r: &mut Receipt| r.telemetry_status = "observed".to_string(),
            |r: &mut Receipt| r.exit_status = "exit(1)".to_string(),
            |r: &mut Receipt| r.invocation_id = "replay".to_string(),
            |r: &mut Receipt| r.outer_sandbox.capabilities_dropped = true,
        ] {
            let mut tampered = r.clone();
            mutate(&mut tampered);
            assert!(
                !tampered.verify_digest(),
                "tamper went undetected"
            );
        }
    }

    #[test]
    fn digest_is_stable_and_versioned() {
        let mut a = dummy_receipt();
        let mut b = dummy_receipt();
        a.seal();
        b.seal();
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.receipt_version, "litebox-receipt/1");
    }
}
