//! Inner sandbox: LiteBox linux_userland as the OS personality.
//!
//! Runs INSIDE the outer sandbox (child process, after namespaces + seccomp).
//! Mirrors litebox_runner_linux_userland's flow but manifest-driven, with
//! telemetry drain after the guest exits.

use anyhow::{Context, Result};
use std::ffi::CString;
use std::os::fd::RawFd;
use std::sync::Arc;

use crate::sandbox::SandboxConfig;

extern crate alloc;

/// Run the guest. Does not return normally — exits the process with the
/// guest's exit code (like the upstream runner).
pub fn run_guest(config: &SandboxConfig, tar_data: &'static [u8], telemetry_fd: RawFd) -> ! {
    let code = match run_guest_inner(config, tar_data, telemetry_fd) {
        Ok(code) => code,
        Err(e) => {
            // Best effort: report via the telemetry fd, then die.
            let msg = format!("{{\"guest_error\": {e:?}}}\n");
            unsafe {
                libc::write(telemetry_fd, msg.as_ptr() as *const _, msg.len());
            }
            127
        }
    };
    unsafe { libc::_exit(code) };
}

fn run_guest_inner(
    config: &SandboxConfig,
    tar_data: &'static [u8],
    telemetry_fd: RawFd,
) -> Result<i32> {
    use litebox::fs::{in_mem, Mode, UserInfo};
    use litebox_platform_linux_userland::LinuxUserland as Platform;

    // No TUN device: network deny (plus the outer net namespace has zero
    // interfaces, so even a host-level socket could not route).
    let platform = Platform::new(None);

    // Minimal in-mem layer: just /tmp (writable scratch). The program and
    // allowlist files live in the tar (read-only).
    let in_mem = in_mem::InMem::new_initialized(vec![(
        "/tmp".to_string(),
        in_mem::InitialNode::Directory {
            mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
            owner: UserInfo::ROOT,
        },
    )]);

    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    let initial_fs = shim_builder.default_fs(in_mem, std::borrow::Cow::Borrowed(tar_data));
    let initial_fs = Arc::new(initial_fs);
    let shim = shim_builder.build();

    // Guest identity: UID 1000 (matches the tar's world-readable entries).
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
    let ppid = unsafe { libc::getppid() };
    let task_params = litebox_common_linux::TaskParams {
        pid: tid,
        ppid,
        uid: 1000,
        euid: 1000,
        gid: 1000,
        egid: 1000,
    };

    let argv: Vec<CString> = config
        .argv
        .iter()
        .map(|a| CString::new(a.as_bytes()).unwrap())
        .collect();
    // Minimal environment: do not leak host env into the guest.
    let envp: Vec<CString> = vec![
        CString::new("PATH=/bin:/usr/bin").unwrap(),
        CString::new("HOME=/tmp").unwrap(),
    ];

    // Inner seccomp (LiteBox platform's own filter). Stacks with the outer
    // filter; both must allow what the runner needs.
    // Outer seccomp-BPF (deny-by-default, kill). Applied here, after FS setup
    // (like the upstream runner), right before the inner filter.
    crate::sandbox::apply_seccomp_filter().expect("outer seccomp failed");
    Platform::enable_seccomp_filter();

    let program = shim
        .load_program(initial_fs, task_params, &config.program, argv, envp)
        .context("load_program failed")?;

    unsafe {
        litebox_platform_linux_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }

    let exit_code = program.process.wait_for_unix_shell_exit_code();

    // Drain shim telemetry (spin::Mutex -> futex, allowed by seccomp).
    let (syscalls, files) = litebox_shim_linux::telemetry::take();
    let telem = serde_json::json!({
        "syscalls": syscalls.iter().map(|s| serde_json::json!({"nr": s.nr, "ok": s.ok})).collect::<Vec<_>>(),
        "files": files.iter().map(|f| serde_json::json!({"path": f.path, "write": f.write, "ok": f.ok})).collect::<Vec<_>>(),
    });
    let telem_str = serde_json::to_string(&telem).unwrap();
    unsafe {
        libc::write(telemetry_fd, telem_str.as_ptr() as *const _, telem_str.len());
        libc::close(telemetry_fd);
    }

    Ok(exit_code)
}
