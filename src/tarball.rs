//! Build the guest tar: syscall-rewritten program ELF + its loader/libs +
//! allowlist files. All entries world-readable (guest runs as UID 1000).

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// A file to place in the guest tar: host source -> guest absolute path.
struct TarEntry {
    guest_path: String, // e.g. "/bin/echo"
    data: Vec<u8>,
    mode: u32,
}

/// Resolve ELF dependencies via `ldd`.
fn ldd_libs(prog: &Path) -> Result<Vec<PathBuf>> {
    let out = std::process::Command::new("ldd")
        .arg(prog)
        .output()
        .context("failed to run ldd")?;
    if !out.status.success() {
        // Static binary or non-ELF: no deps.
        return Ok(Vec::new());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut libs = Vec::new();
    for line in text.lines() {
        // Formats: "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)"
        //          "\t/lib64/ld-linux-x86-64.so.2 (0x...)"
        let line = line.trim();
        if line.starts_with("linux-vdso") || line.starts_with("linux-gate") {
            continue;
        }
        let path = if let Some(idx) = line.find("=>") {
            line[idx + 2..].trim().split_whitespace().next()
        } else {
            line.split_whitespace().next()
        };
        if let Some(p) = path {
            let pb = PathBuf::from(p);
            if pb.is_absolute() && pb.exists() {
                libs.push(pb);
            }
        }
    }
    Ok(libs)
}

/// Read a host file for inclusion. Returns (data, mode).
fn read_host_file(p: &Path) -> Result<(Vec<u8>, u32)> {
    let data = std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
    let mode = std::fs::metadata(p)?.permissions().mode() & 0o7777;
    // Guest is UID 1000; entries must be world-readable.
    Ok((data, mode | 0o444))
}

/// Build the tar. Returns (tar_bytes, sha256_hex_of_tar).
pub fn build_guest_tar(
    program: &str,
    allowlist: &[String],
) -> Result<(Vec<u8>, String)> {
    let prog_path = Path::new(program);
    let prog_data = std::fs::read(prog_path)
        .with_context(|| format!("read program {}", prog_path.display()))?;

    // Syscall-rewrite the program ELF (best-effort; the outer seccomp is the
    // real boundary — see threat-model.md R2).
    let rewritten = litebox_syscall_rewriter::hook_syscalls_in_elf(&prog_data, None)
        .with_context(|| format!("syscall-rewrite {}", prog_path.display()))?;

    let mut entries: Vec<TarEntry> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut push = |guest_path: String, data: Vec<u8>, mode: u32| {
        if seen.insert(guest_path.clone()) {
            entries.push(TarEntry { guest_path, data, mode });
        }
    };

    // 1. The rewritten program at its guest path.
    let (pdata, pmode) = read_host_file(prog_path)?;
    let _ = pdata;
    push(program.to_string(), rewritten, pmode | 0o111);

    // 2. Loader + libs (NOT rewritten — loaded before main; their syscalls
    //    are constrained by the outer seccomp + mount namespaces).
    for lib in ldd_libs(prog_path)? {
        let guest = lib.to_string_lossy().to_string();
        // Also handle /lib64/ld-linux symlink -> real path mapping.
        let (data, mode) = read_host_file(&lib)?;
        push(guest, data, mode);
        // Ensure the interpreter path the ELF names exists (usually a symlink
        // we resolve; also add common canonical locations if identical).
    }
    // The ELF's PT_INTERP may name /lib64/ld-linux-x86-64.so.2 which is
    // often a symlink to /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2.
    // read_host_file follows symlinks, but the guest path must match what
    // the kernel/loader requests. Add both spellings if they resolve equal.
    for alt in ["/lib64/ld-linux-x86-64.so.2"] {
        let ap = Path::new(alt);
        if ap.exists() {
            if let Ok((data, mode)) = read_host_file(ap) {
                push(alt.to_string(), data, mode);
            }
        }
    }

    // 3. Allowlist entries (files; directories are walked).
    for entry in allowlist {
        let p = Path::new(entry);
        if p == prog_path {
            continue; // already added (rewritten)
        }
        let meta = std::fs::metadata(p)
            .with_context(|| format!("stat allowlist {}", p.display()))?;
        if meta.is_dir() {
            for dir_entry in walkdir_simple(p)? {
                let guest = dir_entry.to_string_lossy().to_string();
                let (data, mode) = read_host_file(&dir_entry)?;
                // Writable bit cleared: allowlist mounts are read-only.
                push(guest, data, mode & !0o222);
            }
        } else {
            let (data, mode) = read_host_file(p)?;
            push(entry.clone(), data, mode & !0o222);
        }
    }

    if entries.is_empty() {
        bail!("no files collected for guest tar");
    }

    // 4. Write the tar (deterministic order for a stable hash).
    entries.sort_by(|a, b| a.guest_path.cmp(&b.guest_path));
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        for e in &entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(e.data.len() as u64);
            header.set_mode(e.mode);
            // Guest identity: root-owned system files, readable by all.
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            let guest_rel = e.guest_path.trim_start_matches('/');
            builder
                .append_data(&mut header, guest_rel, &e.data[..])
                .with_context(|| format!("tar append {}", e.guest_path))?;
        }
        builder.into_inner()?;
    }
    let hash = hex(&Sha256::digest(&tar_data));
    Ok((tar_data, hash))
}

fn walkdir_simple(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            out.extend(walkdir_simple(&p)?);
        } else if ft.is_file() {
            out.push(p);
        }
        // Skip symlinks/specials in the pilot (honest limitation).
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
