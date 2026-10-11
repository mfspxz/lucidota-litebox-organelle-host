//! Organelle manifest: what the governor authorizes the sandbox to run.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Authorization block: the governor's signed grant for this invocation.
/// Absent in local/pilot mode (then the receipt marks authority UNVERIFIED).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAuth {
    /// Who issued the grant, e.g. "exchange-governor".
    pub issuer: String,
    /// Unix seconds: grant becomes valid.
    pub issued_at: u64,
    /// Unix seconds: grant expires. Host rejects expired grants.
    pub expires_at: u64,
    /// Unique per invocation; bound in the signature and the receipt.
    /// Cross-process replay detection needs the durable receipt ledger
    /// (receipt fix); within one host process every invocation is fresh.
    pub invocation_id: String,
    /// Hex Ed25519 signature over the canonical manifest bytes with this
    /// field's value removed (see signing_canonical_json).
    pub signature: String,
}

/// How the host authenticated the manifest (for the receipt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    /// Signature verified against --trusted-key; limits are governor-bound.
    Verified,
    /// No --trusted-key: local/pilot mode, authority string is a claim.
    UnverifiedLocal,
}

/// Result of manifest authentication.
pub struct AuthOutcome {
    pub status: AuthStatus,
    /// What goes in the receipt's authority field: the verified issuer, or
    /// an explicitly-marked unverified claim. Never the raw string alone.
    pub receipt_authority: String,
    pub invocation_id: String,
}

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
    /// Signed authorization block. Required when the host runs with
    /// --trusted-key; optional (unverified-local mode) otherwise.
    #[serde(default)]
    pub auth: Option<ManifestAuth>,
    /// Hex sha256 of the program file. When present AND the manifest is
    /// signature-verified, the host checks the program bytes match before
    /// packaging (binds the exact program to the grant).
    #[serde(default)]
    pub program_sha256: Option<String>,
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
        if self.memory_limit > 64 * 1024 * 1024 * 1024 {
            bail!("memory_limit must be <= 64GiB (host sanity ceiling)");
        }
        if self.cpu_limit > 3600 {
            bail!("cpu_limit must be <= 3600s (host sanity ceiling)");
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

/// Seconds of clock skew tolerated on grant timestamps.
const CLOCK_SKEW_SECS: u64 = 300;

impl Manifest {
    /// Authenticate the manifest against an optional trusted governor key
    /// (hex Ed25519 public key, from --trusted-key).
    ///
    /// - With a trusted key: the manifest MUST carry an auth block with a
    ///   valid, unexpired signature covering the entire manifest (including
    ///   resource limits, command, allowlist, and program hash). Anything
    ///   else is rejected — fail closed.
    /// - Without: local/pilot mode. The authority string is passed through
    ///   explicitly marked UNVERIFIED; the receipt says so.
    pub fn authenticate(&self, trusted_key_hex: Option<&str>) -> Result<AuthOutcome> {
        match trusted_key_hex {
            Some(key_hex) => {
                let auth = self
                    .auth
                    .as_ref()
                    .context("strict mode (--trusted-key): manifest has no auth block; rejected")?;
                let now = unix_now()?;
                if now + CLOCK_SKEW_SECS < auth.issued_at {
                    bail!("grant not yet valid (issued_at in the future)");
                }
                if now > auth.expires_at + CLOCK_SKEW_SECS {
                    bail!("grant expired");
                }
                if auth.issued_at > auth.expires_at {
                    bail!("grant issued_at is after expires_at");
                }
                if auth.issuer.is_empty() {
                    bail!("grant issuer must not be empty");
                }
                if auth.invocation_id.is_empty() {
                    bail!("grant invocation_id must not be empty");
                }
                let msg = self.signing_canonical_json()?;
                verify_ed25519(key_hex, &auth.signature, msg.as_bytes())
                    .context("grant signature invalid; rejected")?;
                // program_sha256, when present, is covered by the signature
                // (it is part of the canonical bytes) and checked against
                // the actual program file during tar build.
                Ok(AuthOutcome {
                    status: AuthStatus::Verified,
                    receipt_authority: format!("verified:{}", auth.issuer),
                    invocation_id: auth.invocation_id.clone(),
                })
            }
            None => Ok(AuthOutcome {
                status: AuthStatus::UnverifiedLocal,
                receipt_authority: format!("UNVERIFIED(local-mode):{}", self.authority),
                invocation_id: self
                    .auth
                    .as_ref()
                    .map(|a| a.invocation_id.clone())
                    .unwrap_or_else(|| "none".to_string()),
            }),
        }
    }

    /// Canonical bytes that the grant signature covers: the full manifest
    /// with auth.signature removed (empty string). The signer MUST construct
    /// the manifest, blank the signature field, canonicalize, sign, then
    /// fill in the signature. Any post-signing mutation invalidates it.
    pub fn signing_canonical_json(&self) -> Result<String> {
        let mut v = serde_json::to_value(self)?;
        if let Some(auth) = v.get_mut("auth") {
            if let Some(sig) = auth.get_mut("signature") {
                *sig = serde_json::Value::String(String::new());
            }
        }
        Ok(canonical(&v))
    }
}

fn unix_now() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_secs())
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("hex string has odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex character")
        })
        .collect()
}

fn verify_ed25519(key_hex: &str, sig_hex: &str, msg: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key_bytes = hex_decode(key_hex).context("bad trusted-key hex")?;
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("trusted-key must be 32 bytes"))?;
    let sig_bytes = hex_decode(sig_hex).context("bad signature hex")?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let vk = VerifyingKey::from_bytes(&key_arr).context("bad Ed25519 public key")?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig).context("Ed25519 verification failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Fixed test keypair (deterministic; NEVER a real key).
    fn test_keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk_hex = hex_bytes(&sk.verifying_key().to_bytes());
        (sk, pk_hex)
    }

    fn hex_bytes(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn base_manifest() -> Manifest {
        Manifest::parse(
            r#"{
            "organelle_id": "test-org",
            "authority": "claimed-authority",
            "command": ["/bin/true"],
            "filesystem_allowlist": [],
            "network": "deny",
            "cpu_limit": 10,
            "memory_limit": 268435456,
            "timeout_secs": 30
        }"#,
        )
        .unwrap()
    }

    fn now() -> u64 {
        unix_now().unwrap()
    }

    /// Attach a signed auth block using the test key.
    fn sign_manifest(sk: &SigningKey, m: &mut Manifest, issued_at: u64, expires_at: u64) {
        m.auth = Some(ManifestAuth {
            issuer: "test-issuer".to_string(),
            issued_at,
            expires_at,
            invocation_id: "inv-001".to_string(),
            signature: String::new(),
        });
        let msg = m.signing_canonical_json().unwrap();
        let sig = sk.sign(msg.as_bytes());
        m.auth.as_mut().unwrap().signature = hex_bytes(&sig.to_bytes());
    }

    #[test]
    fn auth_verified_accepts() {
        let (sk, pk) = test_keypair();
        let mut m = base_manifest();
        let t = now();
        sign_manifest(&sk, &mut m, t - 60, t + 3600);
        let out = m.authenticate(Some(&pk)).unwrap();
        assert_eq!(out.status, AuthStatus::Verified);
        assert_eq!(out.receipt_authority, "verified:test-issuer");
        assert_eq!(out.invocation_id, "inv-001");
    }

    #[test]
    fn auth_tampered_limit_rejected() {
        let (sk, pk) = test_keypair();
        let mut m = base_manifest();
        let t = now();
        sign_manifest(&sk, &mut m, t - 60, t + 3600);
        // Tamper AFTER signing: resource limit escalation must invalidate.
        m.memory_limit *= 2;
        assert!(m.authenticate(Some(&pk)).is_err());
    }

    #[test]
    fn auth_tampered_command_rejected() {
        let (sk, pk) = test_keypair();
        let mut m = base_manifest();
        let t = now();
        sign_manifest(&sk, &mut m, t - 60, t + 3600);
        m.command = vec!["/bin/evil".to_string()];
        assert!(m.authenticate(Some(&pk)).is_err());
    }

    #[test]
    fn auth_expired_rejected() {
        let (sk, pk) = test_keypair();
        let mut m = base_manifest();
        let t = now();
        sign_manifest(&sk, &mut m, t - 7200, t - 3600);
        assert!(m.authenticate(Some(&pk)).is_err());
    }

    #[test]
    fn auth_wrong_key_rejected() {
        let (sk, _) = test_keypair();
        let other = SigningKey::from_bytes(&[0x99u8; 32]);
        let other_pk = hex_bytes(&other.verifying_key().to_bytes());
        let mut m = base_manifest();
        let t = now();
        sign_manifest(&sk, &mut m, t - 60, t + 3600);
        assert!(m.authenticate(Some(&other_pk)).is_err());
    }

    #[test]
    fn auth_missing_block_rejected_in_strict_mode() {
        let (_, pk) = test_keypair();
        let m = base_manifest();
        assert!(m.authenticate(Some(&pk)).is_err());
    }

    #[test]
    fn auth_unsigned_ok_in_local_mode_but_marked() {
        let m = base_manifest();
        let out = m.authenticate(None).unwrap();
        assert_eq!(out.status, AuthStatus::UnverifiedLocal);
        assert!(out.receipt_authority.starts_with("UNVERIFIED"));
        assert!(out.receipt_authority.contains("claimed-authority"));
    }

    #[test]
    fn auth_cannot_escalate_clone_unsinged() {
        // allow_clone=true without a signature is accepted locally (pilot
        // trust model) but the receipt marks it UNVERIFIED; in strict mode
        // the whole manifest must be signed, so this shape cannot occur.
        let (_, pk) = test_keypair();
        let mut m = base_manifest();
        m.allow_clone = true;
        assert!(m.authenticate(Some(&pk)).is_err()); // no auth block at all
        let out = m.authenticate(None).unwrap();
        assert!(out.receipt_authority.starts_with("UNVERIFIED"));
    }
}
