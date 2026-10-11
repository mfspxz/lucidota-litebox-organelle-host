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

/// Resolve ELF dependencies by PARSING the file. Never executes anything.
///
/// Returns (interpreter_path, resolved_library_paths). Non-ELF input yields
/// empty results (no deps); truncated/malformed ELF is an error (fail closed).
/// This replaces the old `ldd` invocation: `ldd` executes the target (via
/// LD_TRACE_LOADED_OBJECTS, and falls back to direct execution for non-ELF
/// files), so running it on a hostile binary is arbitrary code execution on
/// the host. Parsing bytes can never execute the target.
fn elf_deps(data: &[u8]) -> Result<(Option<String>, Vec<PathBuf>)> {
    let (interp, needed) = parse_elf_dynamic(data)?;
    let mut libs = Vec::new();
    let mut seen = HashSet::new();
    for soname in needed {
        let path = resolve_soname(&soname).with_context(|| {
            format!("cannot resolve DT_NEEDED {soname} in fixed search dirs (fail closed)")
        })?;
        if seen.insert(path.clone()) {
            libs.push(path);
        }
    }
    Ok((interp, libs))
}

/// Fixed host library search dirs (deterministic; no LD_LIBRARY_PATH,
/// no ld.so.cache — the sandbox must not depend on ambient host config).
const LIB_SEARCH_DIRS: &[&str] = &[
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
];

fn resolve_soname(soname: &str) -> Result<PathBuf> {
    // Absolute DT_NEEDED is unusual but legal: use as-is if it exists.
    if soname.starts_with('/') {
        let p = PathBuf::from(soname);
        if p.is_file() {
            return Ok(p);
        }
        bail!("absolute DT_NEEDED not found: {soname}");
    }
    // Refuse path traversal in sonames (fail closed).
    if soname.contains('/') || soname.contains('\0') {
        bail!("DT_NEEDED with path components refused: {soname}");
    }
    for dir in LIB_SEARCH_DIRS {
        let p = PathBuf::from(dir).join(soname);
        if p.is_file() {
            return Ok(p);
        }
    }
    bail!("DT_NEEDED {soname} not found in fixed search dirs")
}

/// Parse PT_INTERP + DT_NEEDED from ELF64 bytes. Pure parsing: no exec.
fn parse_elf_dynamic(data: &[u8]) -> Result<(Option<String>, Vec<String>)> {
    // Not ELF at all (e.g. a script): no dynamic deps, and crucially we do
    // NOT attempt to execute it to find out.
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Ok((None, Vec::new()));
    }
    if data[4] != 2 {
        bail!("only ELF64 supported (class {})", data[4]);
    }
    if data[5] != 1 {
        bail!("only little-endian ELF supported");
    }
    let e_phoff = read_u64(data, 0x20)?;
    let e_phentsize = read_u16(data, 0x36)? as usize;
    let e_phnum = read_u16(data, 0x38)? as usize;
    if e_phentsize < 56 {
        bail!("program header entry size too small: {e_phentsize}");
    }

    let mut interp: Option<String> = None;
    let mut dyn_off: Option<u64> = None;
    let mut loads: Vec<(u64, u64, u64)> = Vec::new(); // (vaddr, filesz, offset)
    for i in 0..e_phnum {
        let off = e_phoff as usize + i * e_phentsize;
        let p_type = read_u32(data, off)?;
        let p_offset = read_u64(data, off + 8)?;
        let p_vaddr = read_u64(data, off + 16)?;
        let p_filesz = read_u64(data, off + 32)?;
        match p_type {
            1 => loads.push((p_vaddr, p_filesz, p_offset)), // PT_LOAD
            2 => dyn_off = Some(p_offset),                 // PT_DYNAMIC
            3 => {
                // PT_INTERP: NUL-terminated path string in the file.
                let s = read_cstr(data, p_offset, p_filesz)?;
                interp = Some(s);
            }
            _ => {}
        }
    }

    let mut needed = Vec::new();
    if let Some(doff) = dyn_off {
        // First pass: collect DT_NEEDED string-table offsets + locate strtab.
        let mut strtab_vaddr: Option<u64> = None;
        let mut needed_offs: Vec<u64> = Vec::new();
        let mut off = doff as usize;
        loop {
            let d_tag = read_i64(data, off)? as i64;
            let d_val = read_u64(data, off + 8)?;
            match d_tag {
                0 => break, // DT_NULL
                1 => needed_offs.push(d_val),
                5 => strtab_vaddr = Some(d_val), // DT_STRTAB
                _ => {}
            }
            off += 16;
            if off + 16 > data.len() {
                bail!("dynamic section runs past end of file");
            }
        }
        let stv = strtab_vaddr.context("PT_DYNAMIC without DT_STRTAB")?;
        // Map the strtab vaddr back to a file offset via PT_LOAD segments.
        let mut strtab_off: Option<u64> = None;
        for (vaddr, filesz, poff) in &loads {
            if stv >= *vaddr && stv < *vaddr + *filesz {
                strtab_off = Some(stv - *vaddr + *poff);
                break;
            }
        }
        let sto = strtab_off.context("DT_STRTAB vaddr not covered by any PT_LOAD")?;
        for noff in needed_offs {
            needed.push(read_cstr(data, sto + noff, u64::MAX)?);
        }
    }
    Ok((interp, needed))
}

fn read_u16(d: &[u8], off: usize) -> Result<u16> {
    let b: [u8; 2] = d.get(off..off + 2).context("ELF read past end")?.try_into().unwrap();
    Ok(u16::from_le_bytes(b))
}
fn read_u32(d: &[u8], off: usize) -> Result<u32> {
    let b: [u8; 4] = d.get(off..off + 4).context("ELF read past end")?.try_into().unwrap();
    Ok(u32::from_le_bytes(b))
}
fn read_u64(d: &[u8], off: usize) -> Result<u64> {
    let b: [u8; 8] = d.get(off..off + 8).context("ELF read past end")?.try_into().unwrap();
    Ok(u64::from_le_bytes(b))
}
fn read_i64(d: &[u8], off: usize) -> Result<i64> {
    Ok(read_u64(d, off)? as i64)
}
fn read_cstr(d: &[u8], off: u64, max: u64) -> Result<String> {
    let off = off as usize;
    let max = max.min((d.len().saturating_sub(off)) as u64) as usize;
    let slice = d.get(off..off + max).context("ELF string read past end")?;
    let end = slice.iter().position(|&b| b == 0).context("unterminated ELF string")?;
    String::from_utf8(slice[..end].to_vec()).context("non-UTF8 ELF string")
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

    // 2. Loader + libs, resolved by PARSING the ELF (never executed).
    // The interpreter is read as bytes only; the guest path matches the
    // PT_INTERP string exactly (no /lib64 alt-spelling guessing needed).
    let (interp, libs) = elf_deps(&prog_data)?;
    if let Some(ip) = interp {
        let ipath = Path::new(&ip);
        if !ipath.is_absolute() {
            bail!("PT_INTERP is not absolute (fail closed): {ip}");
        }
        let (data, mode) = read_host_file(ipath)
            .with_context(|| format!("read interpreter {ip}"))?;
        push(ip, data, mode);
    }
    for lib in libs {
        let guest = lib.to_string_lossy().to_string();
        let (data, mode) = read_host_file(&lib)?;
        push(guest, data, mode);
    }

    // 3. Allowlist entries (files; directories are walked).
    //
    // The tar is the SOLE file-ingress path into the guest (no bind mounts;
    // see sandbox.rs setup_mounts NOTE). Symlink entries are REFUSED, fail
    // closed: following them would silently widen the guest-visible set
    // beyond the literal allowlist entry (a symlink to a directory would
    // tar the entire target tree). Directory walks already skip symlinks
    // (walkdir_simple only descends real dirs / copies real files).
    for entry in allowlist {
        let p = Path::new(entry);
        if p == prog_path {
            continue; // already added (rewritten)
        }
        let link_meta = std::fs::symlink_metadata(p)
            .with_context(|| format!("stat allowlist {}", p.display()))?;
        if link_meta.file_type().is_symlink() {
            bail!(
                "allowlist entry is a symlink (refused, fail closed): {}",
                p.display()
            );
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

    // 4. Write the tar.
    //
    // USTAR format (not GNU): the LiteBox guest's tar parser (tar_no_std)
    // does NOT understand GNU 'L' (longname) entries — worse, its entry
    // iterator silently TERMINATES at the first 'L' entry, dropping every
    // later entry from the guest's filesystem index (observed: a >100-char
    // allowlist path caused the loader/libs to vanish -> ENOENT). USTAR
    // prefix-splitting (up to 255 bytes total) is understood by tar_no_std.
    // Paths that fit neither fail closed here via the explicit length guard.
    for e in &entries {
        if e.guest_path.len() > 255 {
            bail!(
                "guest path exceeds ustar maximum (255 bytes), refused: {}",
                e.guest_path
            );
        }
    }
    entries.sort_by(|a, b| a.guest_path.cmp(&b.guest_path));
    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        for e in &entries {
            let mut header = tar::Header::new_ustar();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tarball-test-{name}-{}", std::process::id()))
    }

    /// P0 regression: a non-ELF "program" (shell script) must be parsed, never
    /// executed. The old `ldd` path would run this.
    #[test]
    fn non_elf_is_never_executed() {
        let marker = tmp_path("marker");
        let script = tmp_path("evil.sh");
        let _ = std::fs::remove_file(&marker);
        let mut f = std::fs::File::create(&script).unwrap();
        writeln!(f, "#!/bin/sh").unwrap();
        writeln!(f, "touch {}", marker.display()).unwrap();
        drop(f);
        let data = std::fs::read(&script).unwrap();
        let (interp, libs) = elf_deps(&data).unwrap();
        assert!(interp.is_none());
        assert!(libs.is_empty());
        assert!(
            !marker.exists(),
            "hostile script was EXECUTED during dep resolution"
        );
        let _ = std::fs::remove_file(&script);
    }

    /// P0 regression: an ELF naming a hostile PT_INTERP is parsed, never
    /// executed. Synthesizes a minimal ELF64 with PT_INTERP pointing at a
    /// script that would touch a marker if run.
    #[test]
    fn hostile_interp_is_never_executed() {
        let marker = tmp_path("interp-marker");
        let interp_path = tmp_path("evil-interp");
        let _ = std::fs::remove_file(&marker);
        // The "interpreter": a script that touches the marker if executed.
        let mut f = std::fs::File::create(&interp_path).unwrap();
        writeln!(f, "#!/bin/sh").unwrap();
        writeln!(f, "touch {}", marker.display()).unwrap();
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&interp_path).unwrap().permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(&interp_path, p).unwrap();
        }

        // Minimal ELF64: ehdr + 1 phdr (PT_INTERP).
        let interp_bytes = interp_path.to_string_lossy();
        let ib = interp_bytes.as_bytes();
        let mut elf = vec![0u8; 64 + 56 + ib.len() + 1];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELF64
        elf[5] = 1; // LE
        elf[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        elf[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        let ph = 64usize;
        elf[ph..ph + 4].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        elf[ph + 8..ph + 16].copy_from_slice(&(120u64).to_le_bytes()); // p_offset
        elf[ph + 32..ph + 40].copy_from_slice(&(ib.len() as u64 + 1).to_le_bytes()); // p_filesz
        elf[120..120 + ib.len()].copy_from_slice(ib);

        let (interp, libs) = elf_deps(&elf).unwrap();
        assert_eq!(interp.as_deref(), Some(interp_path.to_str().unwrap()));
        assert!(libs.is_empty());
        assert!(
            !marker.exists(),
            "hostile interpreter was EXECUTED during dep resolution"
        );
        let _ = std::fs::remove_file(&interp_path);
    }

    /// A real dynamic ELF resolves to existing absolute library paths.
    #[test]
    fn real_elf_resolves_libs() {
        let data = std::fs::read("/bin/true").unwrap();
        let (interp, libs) = elf_deps(&data).unwrap();
        assert!(interp.is_some(), "expected PT_INTERP on /bin/true");
        assert!(!libs.is_empty(), "expected DT_NEEDED libs on /bin/true");
        assert!(libs.iter().any(|p| p.to_string_lossy().contains("libc.so")));
        for p in &libs {
            assert!(p.is_absolute());
            assert!(p.is_file(), "resolved lib missing: {}", p.display());
        }
    }

    /// Truncated ELF fails closed (error, not silent empty deps).
    #[test]
    fn truncated_elf_fails_closed() {
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        // e_phoff points past the end.
        elf[0x20..0x28].copy_from_slice(&4096u64.to_le_bytes());
        elf[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        elf[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
        assert!(elf_deps(&elf).is_err());
    }

    /// Soname with path traversal is refused.
    #[test]
    fn traversal_soname_refused() {
        assert!(resolve_soname("../../etc/evil.so").is_err());
        assert!(resolve_soname("libc.so.6").is_ok());
    }
}
