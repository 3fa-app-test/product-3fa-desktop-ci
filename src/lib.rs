//! `threefa_core` — the platform-independent heart of the 3FA desktop
//! authenticator: OTP generation, the encrypted vault, authentication factors,
//! the session/auto-lock state machine, and the zero-knowledge sync client.
//!
//! The GUI binary (`main.rs`) is a thin Slint shell over this library; keeping
//! the logic here means it is all unit-testable without a display server.

pub mod app_state;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod otp;
pub mod pin_session;
pub mod protocol;
pub mod qr;
pub mod session;
pub mod sync;
pub mod vault;

/// Default on-disk vault filename within the app's data directory.
pub const VAULT_FILENAME: &str = "default.vault";

/// Atomically write `bytes` to `path` with owner-only permissions.
///
/// The sealed vault is the single source of truth for a user's OTP seeds, so the
/// write must be crash-safe: we write to a sibling temp file, `fsync` it, then
/// `rename` it over the target. A power loss mid-write therefore leaves either
/// the old vault or the new one intact — never a truncated/empty file. On Unix
/// the temp file is created `0600` so the sealed blob is never even briefly
/// group/world-readable (defence-in-depth on top of the AEAD encryption).
pub fn write_private_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("vault");
    // Same directory ⇒ same filesystem ⇒ `rename` is atomic. PID keeps
    // concurrent app instances from colliding on the temp name.
    let tmp = dir.join(format!(".{file_name}.tmp-{}", std::process::id()));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let write_result = (|| -> std::io::Result<()> {
        let mut f = opts.open(&tmp)?;
        // `mode()` only applies on *creation*; re-tighten in case a stale temp
        // file from a previous crash was reused, or the platform ignored it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    std::fs::rename(&tmp, path)
}

/// Resolve the per-user data directory where the vault is stored. Uses platform
/// conventions; falls back to the current directory if none is discoverable.
pub fn data_dir() -> std::path::PathBuf {
    // XDG / Application Support / AppData, without pulling a crate: read the
    // documented env vars directly.
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::Path::new(&home).join("Library/Application Support/3FA");
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return std::path::Path::new(&appdata).join("3FA");
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return std::path::Path::new(&xdg).join("3fa");
        }
        if let Ok(home) = std::env::var("HOME") {
            return std::path::Path::new(&home).join(".local/share/3fa");
        }
    }
    std::path::PathBuf::from(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("3fa-test-{}-{}", std::process::id(), name));
        p
    }

    #[test]
    fn write_private_atomic_round_trips_and_replaces() {
        let path = tmp_path("vault");
        let _ = std::fs::remove_file(&path);

        write_private_atomic(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        // Overwriting replaces the contents in place (atomic rename).
        write_private_atomic(&path, b"second-and-longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second-and-longer");

        // No temp file is left behind in the directory.
        let leftover = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains(".vault.tmp-"));
        assert!(!leftover, "temp file should have been renamed away");

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_atomic_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_path("perms");
        let _ = std::fs::remove_file(&path);

        write_private_atomic(&path, b"secret-sealed-blob").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vault file must be readable only by its owner");

        let _ = std::fs::remove_file(&path);
    }
}
