//! Slint GUI controller: binds the declarative `ui/app.slint` shell to the
//! `threefa_core` library. Owns the live app state (passcode buffer, unlocked
//! vault + DEK, session timers) and refreshes OTP codes once per second.
//!
//! This module only exists in `gui` builds.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use slint::{ModelRc, Timer, TimerMode, VecModel};
use zeroize::{Zeroize, Zeroizing};

/// How long a copied OTP code is allowed to sit on the clipboard before we wipe
/// it (if it hasn't already been replaced by something the user copied).
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(20);

use threefa_core::app_state::{Phase as VaultPhase, VaultLifecycle};
use threefa_core::auth::{FactorProof, PolicyEngine};
use threefa_core::config::{config_path, SyncConfig};
use threefa_core::crypto::SecretKey;
use threefa_core::otp::uri::OtpAccount;
use threefa_core::pin_session::{self, PinGate, PinGuard, SealedSessionFile, SessionSecrets};
use threefa_core::session::{Interaction, PollResult, Session};
use threefa_core::sync::http;
use threefa_core::sync::supabase::{self, SupabaseConfig};
use threefa_core::vault::{StoredAccount, VaultData, VaultFile};
use threefa_core::{data_dir, VAULT_FILENAME};

/// Wipe-after-N threshold for PIN attempts (see [`PinGuard`]).
const MAX_PIN_FAILURES: u32 = 10;

slint::include_modules!();

/// Live application state, shared into Slint callbacks via `Rc<RefCell<…>>`.
struct AppState {
    vault_path: std::path::PathBuf,
    file: Option<VaultFile>,
    data: Option<VaultData>,
    dek: Option<SecretKey>,
    lifecycle: VaultLifecycle,
    session: Session,
    /// In-progress passcode entry.
    entry: String,
    /// Non-secret sync config (server URL, username, stable device id).
    sync_cfg: SyncConfig,
    /// Path to `config.json` beside the vault.
    config_path: std::path::PathBuf,
}

impl AppState {
    fn lock(&mut self) {
        self.lifecycle.lock();
        // Drop decrypted material; SecretKey/VaultData zeroize on drop.
        self.data = None;
        self.dek = None;
        // Wipe the passcode buffer's bytes, not just reset its length.
        self.entry.zeroize();
        self.session.lock();
        self.assert_lifecycle_invariant();
    }

    fn dispose(&mut self) {
        self.lifecycle.dispose();
        self.data = None;
        self.dek = None;
        self.entry.zeroize();
        self.session.lock();
        self.assert_lifecycle_invariant();
    }

    fn assert_lifecycle_invariant(&self) {
        let has_material = self.data.is_some() && self.dek.is_some();
        debug_assert_eq!(
            self.lifecycle.phase() == VaultPhase::Unlocked,
            has_material,
            "decrypted vault material must exist iff lifecycle is unlocked"
        );
    }

    fn policy_engine(&self) -> PolicyEngine {
        let policy = self.data.as_ref().map(|d| d.policy).unwrap_or_default();
        PolicyEngine::new(policy)
    }
}

/// Report a GUI interaction to the session's idle timer.
///
/// Every Slint callback that represents the user *doing something* funnels
/// through here; whether a given [`Interaction`] actually resets the timer is
/// decided by [`Interaction::is_user_activity`] in the library, which is where
/// it is unit-tested — this module has no tests of its own, and CI's `gui` job
/// compiles and lints it but never exercises it. Takes the borrow for the
/// shortest possible moment so it can be called next to other borrows.
fn note_activity(state: &Rc<RefCell<AppState>>, interaction: Interaction) {
    state
        .borrow_mut()
        .session
        .note_interaction(interaction, Instant::now());
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Entry point invoked from `main.rs`.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = {
        let dir = data_dir();
        let _ = std::fs::create_dir_all(&dir);
        // Restrict the data directory to the owner so other local accounts can't
        // read the (encrypted, but salt-bearing) vault for an offline guess.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        dir.join(VAULT_FILENAME)
    };

    // Load any existing sealed vault file (still locked).
    let file = std::fs::read(&vault_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<VaultFile>(&bytes).ok());
    let mut lifecycle = VaultLifecycle::new();
    assert!(lifecycle.initialize(file.is_some()));
    let setup = lifecycle.phase() == VaultPhase::Setup;

    let cfg_path = config_path();
    let mut sync_cfg = SyncConfig::load(&cfg_path);
    // Generate + persist a stable device id on first run (this device's key in the
    // sync version vector).
    let id_before = sync_cfg.device_id.clone();
    sync_cfg.ensure_device_id();
    if sync_cfg.device_id != id_before {
        let _ = sync_cfg.save(&cfg_path);
    }

    let state = Rc::new(RefCell::new(AppState {
        vault_path,
        file,
        data: None,
        dek: None,
        lifecycle,
        session: Session::new(),
        // Pre-size to the passcode length so pushing digits never reallocates
        // (a realloc would copy the secret into a freed heap block we can't wipe).
        entry: String::with_capacity(8),
        sync_cfg,
        config_path: cfg_path,
    }));

    let app = AppWindow::new()?;
    app.set_screen(if setup { "setup".into() } else { "lock".into() });
    {
        let s = state.borrow();
        app.set_sync_server(s.sync_cfg.server_url().unwrap_or_default().into());
        app.set_sync_username(s.sync_cfg.username.clone().into());
    }
    // Native factors are stubbed for now (see auth::biometric); hide their
    // buttons until a real backend reports availability.
    app.set_biometric_available(false);
    app.set_passkey_available(false);
    app.set_voice_available(false);
    // The "Scan camera" button only appears in builds that include the camera
    // stack; image-import scanning is always available.
    app.set_camera_available(cfg!(feature = "camera"));

    wire_callbacks(&app, &state);
    spawn_tick(&app, &state);

    app.run()?;
    state.borrow_mut().dispose();
    Ok(())
}

fn wire_callbacks(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let weak = app.as_weak();

    // --- digit pressed on the passcode pad ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_key_pressed(move |digit| {
            let Some(app) = weak.upgrade() else { return };
            let auto_submit;
            {
                let mut s = state.borrow_mut();
                s.session
                    .note_interaction(Interaction::KeypadInput, Instant::now());
                if s.entry.len() < 6 {
                    s.entry.push_str(&digit);
                }
                app.set_entered_length(s.entry.len() as i32);
                auto_submit = s.entry.len() == 6;
            }
            if auto_submit {
                handle_passcode_submit(&app, &state);
            }
        });
    }

    // --- backspace ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_key_backspace(move || {
            let Some(app) = weak.upgrade() else { return };
            let mut s = state.borrow_mut();
            s.session
                .note_interaction(Interaction::KeypadInput, Instant::now());
            s.entry.pop();
            app.set_entered_length(s.entry.len() as i32);
        });
    }

    // --- add account from otpauth:// uri (typed/pasted) ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_add_account(move |uri| {
            let Some(app) = weak.upgrade() else { return };
            note_activity(&state, Interaction::AddAccount);
            apply_otpauth_uri(&app, &state, uri.as_str());
        });
    }

    // --- add account by scanning a QR from an image / screenshot ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_scan_image(move || {
            let Some(app) = weak.upgrade() else { return };
            note_activity(&state, Interaction::ScanQr);
            let picked = rfd::FileDialog::new()
                .add_filter("QR image", &["png", "jpg", "jpeg", "webp", "bmp"])
                .set_title("Choose a QR code image")
                .pick_file();
            let Some(path) = picked else { return };
            match threefa_core::qr::decode_image_path(&path) {
                Ok(uri) => apply_otpauth_uri(&app, &state, &uri),
                // `QrError`'s messages are self-contained (and name the bulk-export
                // case specifically), so show them as-is rather than under a
                // "no otpauth QR found" prefix that would be wrong for most of them.
                Err(e) => app.set_status(e.to_string().into()),
            }
        });
    }

    // --- add account by scanning a QR from the webcam (feature `camera`) ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_scan_camera(move || {
            let Some(app) = weak.upgrade() else { return };
            note_activity(&state, Interaction::ScanQr);
            #[cfg(feature = "camera")]
            {
                // NOTE: blocking grab for up to 12s; a future pass can move this to
                // a worker thread so the UI stays responsive while scanning.
                app.set_status("Scanning — hold the QR up to the camera…".into());
                match threefa_core::qr::scan_camera(std::time::Duration::from_secs(12)) {
                    Ok(uri) => apply_otpauth_uri(&app, &state, &uri),
                    Err(e) => app.set_status(e.to_string().into()),
                }
            }
            #[cfg(not(feature = "camera"))]
            {
                app.set_status("Rebuild with `--features camera` to scan from the webcam".into());
            }
        });
    }

    // --- copy a code to the clipboard ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_copy_code(move |id| {
            let Some(app) = weak.upgrade() else { return };
            note_activity(&state, Interaction::CopyCode);
            let s = state.borrow();
            if let Some(data) = s.data.as_ref() {
                if let Some(acct) = data.accounts.iter().find(|a| a.id == id.as_str()) {
                    if let Ok(code) = acct.current_code(now_unix()) {
                        set_clipboard(&code);
                        app.set_status("Copied to clipboard".into());
                    }
                }
            }
        });
    }

    // --- spend the current HOTP code and move to the next counter ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_advance_counter(move |id| {
            let Some(app) = weak.upgrade() else { return };
            note_activity(&state, Interaction::AdvanceCounter);
            advance_hotp_counter(&app, &state, id.as_str());
        });
    }

    // --- lock now ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_lock_now(move || {
            let Some(app) = weak.upgrade() else { return };
            // Classified as non-activity: there is no idle timer left to reset.
            note_activity(&state, Interaction::LockNow);
            state.borrow_mut().lock();
            app.set_screen("lock".into());
            app.set_entered_length(0);
            app.set_status("Locked".into());
        });
    }

    // --- extend session (requires a distinct extra factor) ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_extend_session(move || {
            let Some(app) = weak.upgrade() else { return };
            // Deliberately classified as NON-activity: pressing this button must
            // not reset the idle timer as a side effect, or it would extend the
            // session without ever satisfying the second-factor gate below.
            note_activity(&state, Interaction::ExtendRequest);
            let mut s = state.borrow_mut();
            let engine = s.policy_engine();
            // With native factors stubbed, the only available extra factor today
            // is re-presenting the passcode out-of-band. A real biometric/passkey
            // proof would be collected here.
            let proofs: Vec<FactorProof> = collect_available_factor_proofs();
            let ok = s.session.try_extend(Instant::now(), &engine, &proofs);
            drop(s);
            app.set_status(
                if ok {
                    "Session extended"
                } else {
                    "Need a second factor to extend"
                }
                .into(),
            );
        });
    }

    // Native factor buttons — wired but inert until backends report available.
    {
        let weak = weak.clone();
        app.on_use_biometric(move || {
            if let Some(app) = weak.upgrade() {
                app.set_status("Biometric backend not yet enabled".into());
            }
        });
    }
    {
        let weak = weak.clone();
        app.on_use_passkey(move || {
            if let Some(app) = weak.upgrade() {
                app.set_status("Passkey backend not yet enabled".into());
            }
        });
    }
    {
        let weak = weak.clone();
        app.on_use_voice(move || {
            if let Some(app) = weak.upgrade() {
                app.set_status("Voice backend not yet enabled".into());
            }
        });
    }

    // --- open / close the sync+settings screen ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_open_settings(move || {
            if let Some(app) = weak.upgrade() {
                note_activity(&state, Interaction::Navigate);
                app.set_screen("settings".into());
                app.set_sync_status("".into());
            }
        });
    }
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_close_settings(move || {
            if let Some(app) = weak.upgrade() {
                note_activity(&state, Interaction::Navigate);
                let unlocked = state.borrow().data.is_some();
                app.set_screen(if unlocked {
                    "vault".into()
                } else {
                    "lock".into()
                });
            }
        });
    }

    // --- register a new account, then sync ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_sync_register(move |server, username, password| {
            let Some(app) = weak.upgrade() else { return };
            note_activity(&state, Interaction::Sync);
            sync_authenticate(
                &app,
                &state,
                AuthKind::Register,
                server.as_str(),
                username.as_str(),
                password.as_str(),
            );
        });
    }
    // --- log in to an existing account, then sync ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_sync_login(move |server, username, password| {
            let Some(app) = weak.upgrade() else { return };
            note_activity(&state, Interaction::Sync);
            sync_authenticate(
                &app,
                &state,
                AuthKind::Login,
                server.as_str(),
                username.as_str(),
                password.as_str(),
            );
        });
    }
    // --- sync now against the already-authenticated account ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_sync_now(move |server, username, password| {
            let Some(app) = weak.upgrade() else { return };
            note_activity(&state, Interaction::Sync);
            sync_run(
                &app,
                &state,
                server.as_str(),
                username.as_str(),
                password.as_str(),
            );
        });
    }
    // --- Supabase sign-in: identity → enroll device → optional PIN session ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_sync_supabase_signin(move |server, email, password, passphrase, pin| {
            let Some(app) = weak.upgrade() else { return };
            note_activity(&state, Interaction::Sync);
            supabase_signin(
                &app,
                &state,
                server.as_str(),
                email.as_str(),
                password.as_str(),
                passphrase.as_str(),
                pin.as_str(),
            );
        });
    }
    // --- PIN unlock: refresh the Supabase session without email/password ---
    {
        let state = state.clone();
        let weak = weak.clone();
        app.on_sync_pin_unlock(move |server, pin, passphrase| {
            let Some(app) = weak.upgrade() else { return };
            note_activity(&state, Interaction::Sync);
            pin_unlock(
                &app,
                &state,
                server.as_str(),
                pin.as_str(),
                passphrase.as_str(),
            );
        });
    }
}

/// Resolve the Supabase client config (config.json override, else build-time
/// default), or explain what's missing.
fn supabase_config(state: &Rc<RefCell<AppState>>) -> Result<SupabaseConfig, String> {
    let s = state.borrow();
    match (s.sync_cfg.supabase_url(), s.sync_cfg.supabase_anon_key()) {
        (Some(url), Some(key)) => Ok(SupabaseConfig {
            project_url: url.to_string(),
            anon_key: key.to_string(),
        }),
        _ => Err(
            "Supabase is not configured — set supabase_url and supabase_anon_key in config.json"
                .to_string(),
        ),
    }
}

/// Sign in with Supabase, enroll this device with the sync server, store the
/// sync token in the OS keychain, seal a PIN session (if a PIN was provided),
/// then run a sync sealed under the separate passphrase.
fn supabase_signin(
    app: &AppWindow,
    state: &Rc<RefCell<AppState>>,
    server: &str,
    email: &str,
    password: &str,
    passphrase: &str,
    pin: &str,
) {
    if server.is_empty() || email.is_empty() || password.is_empty() {
        app.set_sync_status("Enter server, email and password".into());
        return;
    }
    // Validate the PIN *before* any network work, so a bad PIN can't leave the
    // device enrolled and its token stored with no sealed session to unlock it.
    if !pin.is_empty()
        && (!pin_session::is_valid_format(pin.as_bytes()) || pin_session::is_weak(pin.as_bytes()))
    {
        app.set_sync_status("PIN must be 6 digits and not a trivial sequence".into());
        return;
    }
    let cfg = match supabase_config(state) {
        Ok(c) => c,
        Err(msg) => {
            app.set_sync_status(msg.into());
            return;
        }
    };

    let session = match supabase::sign_in(&cfg, email, password) {
        Ok(s) => s,
        Err(e) => {
            app.set_sync_status(format!("Supabase sign-in failed: {e}").into());
            return;
        }
    };
    let tok = match http::enroll_supabase(server, &session.access_token, "3FA Desktop") {
        Ok(t) => t,
        Err(e) => {
            app.set_sync_status(format!("Device enrollment failed: {e}").into());
            return;
        }
    };
    if let Err(e) = http::keystore::save_token(server, &tok.sync_token) {
        app.set_sync_status(format!("Could not store token: {e}").into());
        return;
    }

    // Seal the refresh + sync tokens under the PIN so an expired access JWT can
    // be refreshed with the PIN alone. Optional: skipping just means a full
    // sign-in on expiry.
    if !pin.is_empty() {
        let secrets = SessionSecrets {
            refresh_token: session.refresh_token.clone(),
            sync_token: tok.sync_token.clone(),
        };
        match pin_session::seal(&secrets, pin.as_bytes()) {
            Ok(sealed) => {
                if let Err(e) = SealedSessionFile::new(sealed).save(&pin_session::session_path()) {
                    app.set_sync_status(format!("Could not store PIN session: {e}").into());
                    return;
                }
            }
            Err(e) => {
                app.set_sync_status(format!("PIN not set: {e}").into());
                return;
            }
        }
    }

    save_sync_identity(app, state, server, email);
    app.set_sync_status("Signed in with Supabase — syncing…".into());
    if passphrase.is_empty() {
        app.set_sync_status(
            "Signed in. Enter your sync passphrase and press Sync now to sync the vault.".into(),
        );
        return;
    }
    sync_run(app, state, server, email, passphrase);
}

/// Unlock the sealed session with the PIN, refresh the Supabase session, rotate
/// the sealed file (Supabase rotates refresh tokens), and sync. Full sign-in is
/// only needed if the refresh token itself was revoked.
fn pin_unlock(
    app: &AppWindow,
    state: &Rc<RefCell<AppState>>,
    server: &str,
    pin: &str,
    passphrase: &str,
) {
    // Fall back to the configured server/username when the fields are blank
    // (typical on a PIN unlock — identity was saved at sign-in).
    let (cfg_server, cfg_user) = {
        let s = state.borrow();
        (
            s.sync_cfg.server_url().unwrap_or_default().to_string(),
            s.sync_cfg.username.clone(),
        )
    };
    let server = if server.is_empty() {
        cfg_server
    } else {
        server.to_string()
    };
    if server.is_empty() {
        app.set_sync_status("Enter the sync server URL".into());
        return;
    }

    let path = pin_session::session_path();
    let Some(mut file) = SealedSessionFile::load(&path) else {
        app.set_sync_status("No PIN session on this device — sign in with Supabase first".into());
        return;
    };

    // Enforce backoff/wipe before touching the sealed blob.
    let guard = PinGuard::from_failures(file.failures, MAX_PIN_FAILURES);
    let since_last_failure = Duration::from_secs(now_unix().saturating_sub(file.last_failure_unix));
    match guard.gate(since_last_failure) {
        PinGate::Allow => {}
        PinGate::Backoff { seconds } => {
            app.set_sync_status(format!("Too many attempts — try again in {seconds}s").into());
            return;
        }
        PinGate::Wipe => {
            let _ = std::fs::remove_file(&path);
            app.set_sync_status(
                "Too many failed PIN attempts — session wiped; sign in with Supabase".into(),
            );
            return;
        }
    }

    let secrets = match pin_session::open(&file.sealed, pin.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            file.failures = file.failures.saturating_add(1);
            file.last_failure_unix = now_unix();
            let wiped = file.failures >= MAX_PIN_FAILURES;
            if wiped {
                let _ = std::fs::remove_file(&path);
            } else {
                let _ = file.save(&path);
            }
            app.set_sync_status(
                if wiped {
                    "Too many failed PIN attempts — session wiped; sign in with Supabase".into()
                } else {
                    format!("PIN rejected: {e}")
                }
                .into(),
            );
            return;
        }
    };

    let cfg = match supabase_config(state) {
        Ok(c) => c,
        Err(msg) => {
            app.set_sync_status(msg.into());
            return;
        }
    };
    let session = match supabase::refresh(&cfg, &secrets.refresh_token) {
        Ok(s) => s,
        Err(e) => {
            app.set_sync_status(
                format!("Session expired ({e}) — sign in with Supabase again").into(),
            );
            return;
        }
    };

    // Re-enroll to get a fresh sync token (covers server-side revocation), and
    // reseal under the same PIN with the rotated refresh token.
    let sync_token = match http::enroll_supabase(&server, &session.access_token, "3FA Desktop") {
        Ok(t) => t.sync_token,
        Err(_) => secrets.sync_token.clone(), // enrollment optional if token still valid
    };
    let _ = http::keystore::save_token(&server, &sync_token);
    let rotated = SessionSecrets {
        refresh_token: session.refresh_token.clone(),
        sync_token: sync_token.clone(),
    };
    if let Ok(sealed) = pin_session::seal(&rotated, pin.as_bytes()) {
        let _ = SealedSessionFile::new(sealed).save(&path);
    }

    app.set_sync_status("Session refreshed with PIN".into());
    if !passphrase.is_empty() {
        sync_run(app, state, &server, &cfg_user, passphrase);
    }
}

enum AuthKind {
    Register,
    Login,
}

/// Persist server/username into config and reflect them in the window.
fn save_sync_identity(
    app: &AppWindow,
    state: &Rc<RefCell<AppState>>,
    server: &str,
    username: &str,
) {
    let mut s = state.borrow_mut();
    s.sync_cfg.server_url = server.to_string();
    s.sync_cfg.username = username.to_string();
    s.sync_cfg.ensure_device_id();
    let path = s.config_path.clone();
    let _ = s.sync_cfg.save(&path);
    app.set_sync_server(server.into());
    app.set_sync_username(username.into());
}

/// Register or log in, store the device token in the OS keychain, then run a sync.
fn sync_authenticate(
    app: &AppWindow,
    state: &Rc<RefCell<AppState>>,
    kind: AuthKind,
    server: &str,
    username: &str,
    password: &str,
) {
    if server.is_empty() || username.is_empty() || password.is_empty() {
        app.set_sync_status("Enter server, username and password".into());
        return;
    }
    let device_name = "3FA Desktop";
    let result = match kind {
        AuthKind::Register => http::register(server, username, password, device_name),
        AuthKind::Login => http::login(server, username, password, device_name),
    };
    match result {
        Ok(tok) => {
            if let Err(e) = http::keystore::save_token(server, &tok.sync_token) {
                app.set_sync_status(format!("Could not store token: {e}").into());
                return;
            }
            save_sync_identity(app, state, server, username);
            app.set_sync_status("Authenticated — syncing…".into());
            sync_run(app, state, server, username, password);
        }
        Err(e) => app.set_sync_status(format!("Auth failed: {e}").into()),
    }
}

/// Pull→merge→push the unlocked vault against the server, then persist the merge.
fn sync_run(
    app: &AppWindow,
    state: &Rc<RefCell<AppState>>,
    server: &str,
    username: &str,
    password: &str,
) {
    if password.is_empty() {
        app.set_sync_status("Enter your account password to sync".into());
        return;
    }
    let Some(token) = http::keystore::load_token(server) else {
        app.set_sync_status("Log in or register first".into());
        return;
    };
    // Snapshot the unlocked vault + device id without holding the borrow across I/O.
    let (local, device_id) = {
        let s = state.borrow();
        let Some(data) = s.data.as_ref() else {
            app.set_sync_status("Unlock the vault before syncing".into());
            return;
        };
        (data.clone(), s.sync_cfg.device_id.clone())
    };

    let mut transport = match http::HttpTransport::new(server, token) {
        Ok(t) => t,
        Err(e) => {
            app.set_sync_status(format!("Transport error: {e}").into());
            return;
        }
    };
    match threefa_core::sync::synchronize(&mut transport, password.as_bytes(), &device_id, &local) {
        Ok((merged, _version)) => {
            save_sync_identity(app, state, server, username);
            {
                let mut s = state.borrow_mut();
                // Clone into a Zeroizing buffer (not `**d`, which would leave a
                // bare `[u8;32]` Copy of the DEK un-wiped on the stack). The clone
                // also releases the borrow of `s.dek` so `s.file` can be taken.
                let dek = match s.dek.as_ref() {
                    Some(d) => d.clone(),
                    None => return,
                };
                let path = s.vault_path.clone();
                if let Some(file) = s.file.as_mut() {
                    let _ = file.reseal(&dek, &merged);
                    persist(&path, file);
                }
                s.data = Some(merged.clone());
            }
            app.set_sync_status(format!("Synced — {} accounts", merged.accounts.len()).into());
            refresh_vault(app, state);
        }
        Err(e) => app.set_sync_status(format!("Sync failed: {e}").into()),
    }
}

/// Try to unlock (or, in setup mode, create) the vault with the 6-digit entry.
fn handle_passcode_submit(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let mut s = state.borrow_mut();
    // Move the passcode out and guarantee it is wiped when this function returns,
    // on every path (success, wrong passcode, or vault-create error).
    let entry = Zeroizing::new(std::mem::take(&mut s.entry));
    app.set_entered_length(0);

    if s.lifecycle.phase() == VaultPhase::Setup {
        let Some(operation) = s.lifecycle.begin_create() else {
            app.set_status("Vault creation is not available in the current state".into());
            return;
        };
        // Create a fresh vault sealed under this passcode.
        let data = VaultData::default();
        match VaultFile::create(entry.as_bytes(), &data) {
            Ok((file, dek)) => {
                persist(&s.vault_path, &file);
                if !s.lifecycle.complete(operation, true) {
                    app.set_status("Vault creation was cancelled by a lock".into());
                    return;
                }
                s.file = Some(file);
                s.data = Some(data);
                s.dek = Some(dek);
                s.session.unlock(Instant::now());
                s.assert_lifecycle_invariant();
                drop(s);
                app.set_screen("vault".into());
                app.set_status("Vault created".into());
                refresh_vault(app, state);
            }
            Err(e) => {
                s.lifecycle.complete(operation, false);
                s.assert_lifecycle_invariant();
                app.set_status(format!("Could not create vault: {e}").into());
            }
        }
        return;
    }

    let Some(operation) = s.lifecycle.begin_unlock() else {
        app.set_status("Vault unlock is not available in the current state".into());
        return;
    };

    let Some(file) = s.file.clone() else {
        s.lifecycle.complete(operation, false);
        app.set_status("No vault found".into());
        return;
    };
    match file.unlock(entry.as_bytes()) {
        Ok((data, dek)) => {
            if !s.lifecycle.complete(operation, true) {
                app.set_status("Vault unlock was cancelled by a lock".into());
                return;
            }
            s.data = Some(data);
            s.dek = Some(dek);
            s.session.unlock(Instant::now());
            s.assert_lifecycle_invariant();
            drop(s);
            app.set_screen("vault".into());
            app.set_status("".into());
            refresh_vault(app, state);
        }
        Err(_) => {
            s.lifecycle.complete(operation, false);
            s.assert_lifecycle_invariant();
            app.set_status("Wrong passcode".into());
        }
    }
}

/// Rebuild the account list model and push it to the window.
fn refresh_vault(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let s = state.borrow();
    let Some(data) = s.data.as_ref() else { return };
    let unix = now_unix();
    let rows: Vec<AccountView> = data
        .accounts
        .iter()
        .map(|a| {
            let code = a.current_code(unix).unwrap_or_else(|_| "------".into());
            let period = a.period.max(1);
            // A counter-based code does not expire, so it has no window to count
            // down; the view hides the ring and shows the counter instead.
            let counter_based = a.is_counter_based();
            let remaining = if counter_based {
                0
            } else {
                period - (unix % period)
            };
            AccountView {
                id: a.id.clone().into(),
                issuer: a.issuer.clone().into(),
                label: a.label.clone().into(),
                code: code.into(),
                seconds: remaining as i32,
                progress: remaining as f32 / period as f32,
                counter_based,
                // Formatted here because `counter` is a u64 and Slint's `int` is
                // an i32 — narrowing it in the view could misreport it.
                counter_label: format!("c{}", a.counter).into(),
            }
        })
        .collect();
    let model: ModelRc<AccountView> = ModelRc::new(VecModel::from(rows));
    app.set_accounts(model);
    // Show whichever deadline fires first (idle timeout vs. hard cap) — the tick
    // refreshes this every second, so it follows the idle timer as activity
    // pushes it out and switches to the cap once the cap is the nearer of the two.
    app.set_lock_seconds(s.session.lock_seconds_remaining(Instant::now()) as i32);
}

/// 1 Hz tick: refresh codes/countdowns and drive the auto-lock state machine.
fn spawn_tick(app: &AppWindow, state: &Rc<RefCell<AppState>>) {
    let weak = app.as_weak();
    let state = state.clone();
    let timer = Timer::default();
    timer.start(
        TimerMode::Repeated,
        std::time::Duration::from_secs(1),
        move || {
            let Some(app) = weak.upgrade() else { return };
            // NB: the tick only polls — it never touches the session
            // (`Interaction::TimerTick` is classified as non-activity), because a
            // self-touching timer would abolish the idle timeout entirely.
            let poll = state.borrow_mut().session.poll(Instant::now());
            match poll {
                PollResult::JustLocked => {
                    state.borrow_mut().lock();
                    app.set_screen("lock".into());
                    app.set_entered_length(0);
                    app.set_status("Auto-locked".into());
                }
                PollResult::Active => {
                    // Only the codes/countdown need refreshing while unlocked.
                    if app.get_screen() == "vault" {
                        refresh_vault(&app, &state);
                    }
                }
                PollResult::Locked => {}
            }
        },
    );
    // Keep the timer alive for the program's lifetime.
    std::mem::forget(timer);
}

/// Today the only collectable factor in the GUI is the passcode (native factors
/// stubbed). Returns an empty set so `try_extend` correctly demands a real second
/// factor; this is the seam where a biometric/passkey/voice proof gets added.
fn collect_available_factor_proofs() -> Vec<FactorProof> {
    Vec::new()
}

/// Enroll an account from a decoded/typed `otpauth://` URI: parse it, append it
/// to the unlocked vault, re-seal under the live DEK, and persist. Shared by the
/// manual "Add" field and both QR scan paths so they all run the same validation
/// and zeroization route (`OtpAccount` wipes its seed on drop).
fn apply_otpauth_uri(app: &AppWindow, state: &Rc<RefCell<AppState>>, uri: &str) {
    // A Google Authenticator bulk-export URI parses as a URL but not as an
    // account, and nothing in the crate expands it — say so plainly instead of
    // letting `from_uri` report "not an otpauth:// URI". (Reached when the user
    // pastes one; the scan paths reject it before they get here.)
    if threefa_core::qr::is_migration_uri(uri) {
        app.set_status(
            threefa_core::qr::QrError::MigrationUnsupported
                .to_string()
                .into(),
        );
        return;
    }
    match OtpAccount::from_uri(uri) {
        Ok(acct) => {
            {
                let mut s = state.borrow_mut();
                // Clone the DEK into a Zeroizing buffer (wiped on drop) rather than
                // `**d`, which would copy the raw key onto the stack un-wiped. The
                // clone also releases the borrow so `s.data`/`s.file` can be taken.
                let dek = match s.dek.as_ref() {
                    Some(d) => d.clone(),
                    None => {
                        app.set_status("Unlock the vault before adding accounts".into());
                        return;
                    }
                };
                let path = s.vault_path.clone();
                if let Some(data) = s.data.as_mut() {
                    data.accounts.push(StoredAccount::from(&acct));
                }
                let snapshot = match s.data.as_ref() {
                    Some(d) => d.clone(),
                    None => return,
                };
                if let Some(file) = s.file.as_mut() {
                    let _ = file.reseal(&dek, &snapshot);
                    persist(&path, file);
                }
            }
            app.set_status("Account added".into());
            refresh_vault(app, state);
        }
        Err(e) => app.set_status(format!("Bad otpauth URI: {e}").into()),
    }
}

/// Spend the HOTP code on screen and move the account to its next counter.
///
/// Reachable only from the "Next code" button. An HOTP code is consumed exactly
/// once and the service accepts only a small look-ahead window, so nothing
/// automatic may call this: not [`spawn_tick`] (the 1 Hz refresh, which only
/// re-renders), not [`sync_run`], not unlocking.
///
/// This is the only code that *advances* a counter. `sync::merge_vault` also
/// assigns one, but only ever adopts a higher counter another device already
/// reached; it never moves past what some device has actually spent.
/// `refresh_vault` only reads.
///
/// The counter is rolled back if the vault write fails, so the code on screen is
/// never one the vault does not hold — otherwise a re-unlock would rewind to a
/// code the user had already used.
fn advance_hotp_counter(app: &AppWindow, state: &Rc<RefCell<AppState>>, id: &str) {
    let outcome = {
        let mut s = state.borrow_mut();
        // Clone the DEK into a Zeroizing buffer (wiped on drop) rather than
        // `**d`, which would copy the raw key onto the stack un-wiped. The clone
        // also releases the borrow so `s.data`/`s.file` can be taken.
        let dek = match s.dek.as_ref() {
            Some(d) => d.clone(),
            None => {
                app.set_status("Unlock the vault before advancing a counter".into());
                return;
            }
        };
        let path = s.vault_path.clone();

        let Some(data) = s.data.as_mut() else { return };
        let Some(account) = data.accounts.iter_mut().find(|a| a.id == id) else {
            return;
        };
        let previous = account.counter;
        if !account.advance_counter() {
            app.set_status(
                if account.is_counter_based() {
                    "This account has reached its counter limit"
                } else {
                    "Only counter-based (HOTP) accounts have a next code"
                }
                .into(),
            );
            return;
        }
        let counter = account.counter;

        let snapshot = match s.data.as_ref() {
            Some(d) => d.clone(),
            None => return,
        };
        let written = {
            let Some(file) = s.file.as_mut() else { return };
            file.reseal(&dek, &snapshot)
                .map_err(|e| e.to_string())
                .and_then(|()| persist_checked(&path, file))
        };

        match written {
            Ok(()) => Ok(counter),
            Err(e) => {
                // Put the counter back: the user has not consumed a code, and a
                // later unlock must not disagree with what is on screen.
                if let Some(data) = s.data.as_mut() {
                    if let Some(account) = data.accounts.iter_mut().find(|a| a.id == id) {
                        account.counter = previous;
                    }
                }
                // Re-seal from the rolled-back data too. `reseal` may have
                // succeeded and only the disk write failed, which would leave the
                // in-memory file holding a counter the user never spent. Every
                // other `persist` call site happens to re-seal first, so nothing
                // would write it today — but that is a global invariant, and this
                // module has no tests to catch it if a future call site breaks it.
                let rolled_back = s.data.clone();
                if let (Some(file), Some(data)) = (s.file.as_mut(), rolled_back.as_ref()) {
                    let _ = file.reseal(&dek, data);
                }
                Err(e)
            }
        }
    };

    match outcome {
        Ok(counter) => {
            app.set_status(
                format!("Now showing code {counter} — the previous one is spent").into(),
            );
            refresh_vault(app, state);
        }
        Err(e) => app.set_status(format!("Could not save the new counter: {e}").into()),
    }
}

/// Atomically write the sealed vault with owner-only permissions.
///
/// The payload is already AEAD-encrypted, but the file still carries the KDF salt
/// and parameters, so we (a) restrict it to mode 0600 to deny other local users a
/// copy for offline passcode guessing, and (b) write-temp-then-`rename` so a crash
/// mid-write can never truncate the live vault into an unparseable state — which
/// the loader would treat as "no vault", silently dropping every enrolled account.
fn persist(path: &std::path::Path, file: &VaultFile) {
    if let Err(e) = persist_checked(path, file) {
        eprintln!("3fa: failed to persist vault to {}: {e}", path.display());
    }
}

/// The write itself, with the failure surfaced instead of logged.
///
/// Callers that merely append (adding an account, storing a sync result) can log
/// and move on; `advance_hotp_counter` cannot, because it has to undo the
/// in-memory counter when the write fails.
fn persist_checked(path: &std::path::Path, file: &VaultFile) -> Result<(), String> {
    // Crash-safe, owner-only write so a power loss mid-save can't truncate the
    // user's only copy of their seeds (see `threefa_core::write_private_atomic`).
    let bytes = serde_json::to_vec(file).map_err(|e| e.to_string())?;
    threefa_core::write_private_atomic(path, &bytes).map_err(|e| e.to_string())
}

pub fn set_clipboard(text: &str) {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        if cb.set_text(text.to_string()).is_ok() {
            schedule_clipboard_clear(text.to_string());
        }
    }
}

/// Wipe the clipboard a short while after copying an OTP code, so a one-time code
/// doesn't linger (and sync to other devices via Universal/Cloud Clipboard). Only
/// clears if our code is still there, to avoid clobbering whatever the user copied
/// in the meantime.
fn schedule_clipboard_clear(value: String) {
    let timer = Timer::default();
    timer.start(TimerMode::SingleShot, CLIPBOARD_CLEAR_AFTER, move || {
        if let Ok(mut cb) = arboard::Clipboard::new() {
            if cb.get_text().map(|c| c == value).unwrap_or(false) {
                let _ = cb.set_text(String::new());
            }
        }
    });
    // Keep the one-shot timer alive until it fires.
    std::mem::forget(timer);
}
