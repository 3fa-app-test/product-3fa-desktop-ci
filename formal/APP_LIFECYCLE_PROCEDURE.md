# Formal-methods procedure: vault lifecycle

`app_lifecycle_model.py` is the bounded exhaustive model for
`src/app_state.rs`. It enumerates legal, illegal, duplicate, and stale
completion events through depth 10. The corresponding production controller in
`src/ui.rs` uses the Rust machine directly; this is not a model that exists only
in tests.

Run:

```bash
just formal
cargo test --no-default-features
```

The checked properties are:

1. Create and unlock are explicit operation phases with unique generation
   tokens. The finite model also checks counter exhaustion: production rejects
   new operations at `u64::MAX` instead of reusing a token.
2. Lock invalidates every outstanding operation.
3. A stale completion cannot move a non-unlocked state to `Unlocked`.
4. Dispose is absorbing.
5. `AppState` owns decrypted `VaultData` and the DEK if and only if the
   production lifecycle is `Unlocked`; lock and dispose drop both.

The session timeout model in `session_model.py` remains a separate refinement:
it decides *when* auto-lock fires, while this model decides which vault states
and operation completions are valid. Together they cover the top-level vault
lifecycle boundary. They do not formally verify Slint, the OS, cryptographic
primitives, or every plugin implementation.
