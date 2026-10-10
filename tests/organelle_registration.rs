//! Organelle migration tests (wave 4b-1): litebox-host (lh) registration.
//!
//! Proves the done-bar for the host experiment: the static manifest matches
//! the Rust `manifest()`, the unit registers on a running `organelle-host`,
//! `describe` runs live with chained receipts, the `run` op fails closed
//! without `litebox.run` and fails honestly on a rejected guest manifest,
//! and suspend/kill each produce receipts.
//!
//! A live sandboxed guest run is NOT asserted here: it needs user namespaces
//! + the LiteBox path deps at runtime. That path is the pilot's proven
//! surface (INTEGRATION.md; tests/hostile/*, the hardening coordinator's
//! lane). Nothing is faked: untestable-here stays unasserted.

use litebox_organelle_host::organelle_impl::litebox_host_organelle;
use organelle_host::{CallContext, CallVerdict, Host};
use serde_json::{json, Value};

fn static_manifest() -> Value {
    let path = format!(
        "{}/../organelles/litebox-host.manifest.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("static manifest present");
    serde_json::from_str(&text).expect("static manifest is valid JSON")
}

#[test]
fn rust_manifest_matches_static_json() {
    let live = serde_json::to_value(litebox_host_organelle().manifest()).unwrap();
    assert_eq!(live, static_manifest(), "manifest drift");
}

#[test]
fn registers_on_host_with_chained_receipts() {
    let host = Host::new();
    host.register(litebox_host_organelle())
        .expect("lh registers (manifest valid)");
    assert!(host
        .list_manifests()
        .iter()
        .any(|m| m.codon == "lh" && m.name == "litebox-host"));
    host.verify_chain().expect("chain verifies after registration");
}

#[test]
fn describe_runs_live_through_host() {
    let host = Host::new();
    host.register(litebox_host_organelle()).unwrap();
    let ctx = CallContext::new("test", vec![]);
    let out = host.call(&ctx, "lh", "describe", json!({})).expect("describe");
    // The real sandbox::describe() output: measured booleans, not assumed.
    assert_eq!(
        out.get("capabilities_dropped").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert!(out.get("seccomp").and_then(|v| v.as_str()).is_some());
    host.verify_chain().expect("chain verifies after invocation");
}

#[test]
fn run_op_fail_closed_without_capability() {
    let host = Host::new();
    host.register(litebox_host_organelle()).unwrap();
    let ctx = CallContext::new("test", vec![]);
    let err = host
        .call(&ctx, "lh", "run", json!({"manifest": {}, "host_bin": "/bin/false"}))
        .expect_err("ExternalEffect op without capability must be denied");
    assert_eq!(err.verdict, CallVerdict::Denied);
    host.verify_chain().expect("chain verifies after denial");
}

#[test]
fn run_op_rejects_bad_guest_manifest_honestly() {
    let host = Host::new();
    host.register(litebox_host_organelle()).unwrap();
    let grant = host.issue_grant("test", vec!["litebox.run".to_string()], 60);
    let host_bin = env!("CARGO_BIN_EXE_litebox-organelle-host");
    // Empty object: the real binary's Manifest::parse rejects it (missing
    // organelle_id/command) -> honest failure, receipted, never faked.
    let err = host
        .call_with_grant(
            &grant,
            None,
            "lh",
            "run",
            json!({"manifest": {}, "host_bin": host_bin}),
        )
        .expect_err("bad guest manifest must fail honestly");
    assert_eq!(err.verdict, CallVerdict::Failed);
    assert!(
        err.reason.contains("organelle_id") || err.reason.contains("manifest"),
        "failure names the cause: {}",
        err.reason
    );
    host.verify_chain().expect("chain verifies after honest failure");
}

#[test]
fn suspend_and_kill_emit_receipts() {
    let host = Host::new();
    host.register(litebox_host_organelle()).unwrap();
    let cp = host.suspend("lh").expect("suspend");
    assert_eq!(cp.codon, "lh");
    // Runs are atomic (receipt or honest failure); the organelle holds no
    // resumable in-memory state, so the checkpoint is honestly ephemeral.
    assert!(cp.ephemeral);
    host.kill("lh").expect("kill");
    host.verify_chain().expect("chain verifies after suspend+kill");
    let kinds: Vec<String> = host
        .receipts()
        .iter()
        .map(|r| format!("{:?}", r.kind))
        .collect();
    assert!(kinds.contains(&"Suspend".to_string()));
    assert!(kinds.contains(&"Checkpoint".to_string()));
    assert!(kinds.contains(&"Kill".to_string()));
}
