//! litebox-host (`lh`) as a native Tier A organelle.
//!
//! Wave 4b-1 organelle migration (verify-against-standard): the repo's one
//! capability unit is the hardened organelle execution host itself — run a
//! guest per a litebox manifest inside the outer Linux sandbox (namespaces,
//! seccomp, rlimits, watchdog) with LiteBox as the inner OS personality,
//! and emit the PL-style receipt JSON.
//!
//! This is a thin capability-contract wrapper: `manifest()` declares the
//! contract, `handle()` delegates to the real binary (`run` op) and the real
//! `sandbox::describe()` (`describe` op). No sandbox logic is reimplemented
//! here.
//!
//! Note the two manifest concepts (see organelles/MAPPING.md): the litebox
//! *guest* manifest (`manifest::Manifest`: organelle_id, authority, command,
//! allowlist, limits) is the governor's authorization for one guest run and
//! is the INPUT to the `run` op; the organelle-migration manifest
//! (`organelles/litebox-host.manifest.json`, codon `lh`) is the capability
//! contract of the host unit itself.

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::sandbox;

fn receipt_policy() -> ReceiptPolicy {
    ReceiptPolicy {
        content_addressed: true,
        algorithm: RECEIPT_ALGORITHM.to_string(),
        chain: true,
    }
}

fn litebox_host_manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "litebox-host".to_string(),
        codon: "lh".to_string(),
        version: "0.1.0".to_string(),
        description: "hardened organelle execution host: run a guest per litebox manifest in the outer Linux sandbox (namespaces, seccomp, rlimits, watchdog), emit the PL-style receipt (organelle)".to_string(),
        contracts: vec![
            Contract {
                op: "describe".to_string(),
                description: "report the outer sandbox actually enforced (measured booleans; no guest is run)".to_string(),
                input_schema: json!({"type":"object","properties":{}}),
                mutation_class: Some(MutationClass::ReadOnly),
                required_capability: None,
            },
            Contract {
                op: "run".to_string(),
                description: "run one guest: write the litebox guest manifest to a temp file, invoke the host binary (run --manifest), return the PL-style receipt JSON".to_string(),
                input_schema: json!({"type":"object","required":["manifest","host_bin"],"properties":{"host_bin":{"type":"string"},"manifest":{"type":"object"}}}),
                mutation_class: Some(MutationClass::ExternalEffect),
                required_capability: Some("litebox.run".to_string()),
            },
        ],
        authority: Authority {
            mutation_class: MutationClass::ExternalEffect,
            declared_valence: Valence::Candidate,
            required_capability: None,
            granted_capabilities: vec![],
        },
        transports: vec![Transport::Native, Transport::UnixSocket],
        receipt_policy: receipt_policy(),
    }
}

fn op_describe() -> Result<Value, OrganelleError> {
    serde_json::to_value(sandbox::describe())
        .map_err(|e| OrganelleError::failed(format!("describe: {e}")))
}

fn op_run(input: &Value) -> Result<Value, OrganelleError> {
    let manifest_obj = input
        .get("manifest")
        .filter(|v| v.is_object())
        .ok_or_else(|| OrganelleError::failed("input.manifest must be an object (litebox guest manifest)"))?;
    let host_bin = input
        .get("host_bin")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OrganelleError::failed("input.host_bin must be the path to the litebox-organelle-host binary"))?;

    // The binary validates the guest manifest itself (Manifest::parse);
    // anything it rejects comes back as an honest failure, never a faked run.
    let tmp = std::env::temp_dir().join(format!(
        "lh-manifest-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&tmp, serde_json::to_string(manifest_obj).unwrap())
        .map_err(|e| OrganelleError::failed(format!("write guest manifest: {e}")))?;

    let out = std::process::Command::new(host_bin)
        .args(["run", "--manifest"])
        .arg(&tmp)
        .output()
        .map_err(|e| OrganelleError::failed(format!("spawn host binary: {e}")))?;
    let _ = std::fs::remove_file(&tmp);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr_tail: String = String::from_utf8_lossy(&out.stderr)
        .lines()
        .rev()
        .take(20)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    match serde_json::from_str::<Value>(stdout.trim()) {
        Ok(receipt) => Ok(json!({
            "receipt": receipt,
            "exit_code": out.status.code(),
            "stderr_tail": stderr_tail,
        })),
        Err(_) => Err(OrganelleError::failed(format!(
            "host binary exited {} without a receipt on stdout; stderr: {}",
            out.status.code().unwrap_or(-1),
            stderr_tail.chars().take(2000).collect::<String>()
        ))),
    }
}

pub struct LiteboxHostOrg {
    manifest: OrganelleManifest,
}

pub fn litebox_host_organelle() -> Arc<dyn Organelle> {
    Arc::new(LiteboxHostOrg {
        manifest: litebox_host_manifest(),
    })
}

impl Organelle for LiteboxHostOrg {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        match op {
            "describe" => op_describe(),
            "run" => op_run(&input),
            _ => Err(OrganelleError::not_found(format!("unknown op: {op}"))),
        }
    }
}
