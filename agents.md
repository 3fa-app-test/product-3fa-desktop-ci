# 3FA-desktop.rs repository agent instructions

These instructions apply to this repository and work performed beneath it.

## Discover instructions hierarchically

Resolve `$PWD`, then walk upward through every parent directory to the filesystem root. Read every readable lowercase `agents.md` on that ancestor chain and apply them in root-to-leaf order. Do not search siblings. Deduplicate resolved paths or inodes, avoid symlink cycles, and report unreadable instruction files.

## Forbidden destructive operations

Never run, script, or suggest any of the following in this repository:

- `rm` or `rm -rf` on tracked or untracked files; stage reviewed removals with `git rm` instead.
- `git rebase`, interactive or otherwise.
- `git reset` in any mode, including `--soft`, `--mixed`, and `--hard`.
- `git push --force`, `--force-with-lease`, or `--force-if-includes`.
- `git filter-repo`, `git filter-branch`, BFG, or any other history-rewriting tool.
- `git clean`.
- `git checkout -- <path>` or `git restore` when it would discard uncommitted work.
- deleting local or remote branches or tags.
- amending commits that have been pushed.

These prohibitions are absolute. Do not weaken them based on an implied authorization.

## Required workflow and remote synchronization

- History is append-only. Fix mistakes with a new commit or `git revert`, never by rewriting shared history.
- Changes land on `main` through small, reviewable feature-branch commits.
- Before editing, preserve existing work, inspect `git status`, the current branch, remotes, and the default branch, run `git fetch --all --prune`, and create the feature branch from the latest remote `main` rather than a stale local copy.
- “Sync with the remote” is a two-way exchange: fetch and merge remote commits, then push local commits. A clean local tree alone is not synchronized.
- Commit or safely stash work before integration. Use `git merge` or `git pull`; never use rebase to synchronize.
- avoid git rebase in favor of git merge.
- Never discard remote commits, bypass review, or bypass required CI.

Concretely, to sync:

1. **Commit your work first** so the tree is clean — pull and merge only into a
   clean tree. `git pull` / `git merge` aborts when an incoming change touches a
   file you have edited, and even when it does not, it buries the merge inside
   your uncommitted work. If you cannot commit yet, `git stash` and `git stash
   pop` after step 3.
2. `git fetch --all --prune` — safe at any time; it only updates tracking refs.
3. `git pull`, or `git merge` the upstream branch, to integrate their commits.
4. `git push` to publish yours.

You are synced only once local and remote hold the same commits; a clean tree
is not evidence of that on its own.

This repository is the source of truth. The copy vendored into `ORESoftware/k8s-cluster` under `remote/deployments/` is a secondary submodule checkout. After merging here, bump that submodule pointer; do not edit the secondary copy directly.

## Canonical interface provenance

`vendor/threefa-interfaces` is an immutable generated snapshot of `3FA-app/3fa-interfaces`, pinned by exact commit and blob IDs in `VENDORED_INTERFACES.toml`. Do not hand-edit it independently. Update it only from the intended canonical interface commit, then run `python3 scripts/check_vendored_interfaces.py` and `cargo test --no-default-features --test interface_pin`.

Deep-link route types, identifier validation, parser semantics, and golden fixtures belong in `3fa-interfaces`. Do not invent repository-local URL shapes that the Flutter companion cannot consume.

## Desktop toolkit contract

Read [`docs/DESKTOP_TOOLKIT.md`](docs/DESKTOP_TOOLKIT.md) before changing UI architecture, platform activation, packaging, or deep links.

- The selected UI kit is **Slint**.
- A WebView is prohibited. Do not add Tauri, Dioxus Desktop, Electron, an embedded browser, or HTML/JS UI rendering.
- Security-sensitive state, route parsing, authorization, vault behavior, and platform credentials remain in Rust.
- Slint markup owns presentation only and must never contain secrets, seeds, recovery material, tokens, or serialized vault data.
- Changing toolkit requires an ADR and coordinated updates to the Flutter companion, `3FA-app/.github`, Linear, and the central strategy document.

## Paired Flutter delivery

The current Flutter companion is `ORESoftware/3fa-client-ui.dart`. The canonical organization-owned migration target is `3FA-app/3fa-flutter`, but it must not be treated as published until verified.

For every desktop-facing feature:

1. inspect both this Rust repository and the current Flutter companion;
2. define shared acceptance criteria and identify affected interfaces, schemas, fixtures, assets, cryptographic formats, deep-link routes, and release behavior;
3. normally update both implementations;
4. when only one changes, record the no-change rationale, companion impact, parity gap, and follow-up work in the issue and pull request;
5. test Rust and Flutter independently and report platform status separately; and
6. keep reciprocal documentation and migration state accurate.

## HTTPS-first deep links

- Canonical form: `https://<verified-3fa-owned-host>/open/<route>?<bounded-query>`.
- Fallback scheme: `threefa://`.
- The production host must not be guessed; document it only after ownership/deployment are verified.
- Treat every URL as untrusted input and validate host, route, version, identifiers, action, and bounded query parameters.
- Never put passwords, bearer/refresh tokens, TOTP/HOTP seeds, recovery secrets, vault material, or encryption keys in URLs.
- Use short-lived, single-use, audience-bound codes for authentication/device-transfer handoffs.
- Support cold start, already-running/single-instance delivery, authentication resume, replay rejection, and browser fallback.
- Require explicit confirmation for enrollment, recovery, device removal, imports, or other security-sensitive actions.

## Build context

This is a standalone repository. CI builds and tests the core headlessly with `--no-default-features`. The default `gui` feature needs Slint's native dependencies; compile and test the full GUI locally on a supported host, but do not try to run the GUI in headless CI.

## Resolve conflicts semantically

Resolve Git conflicts by understanding and combining both sides' intent. Never mechanically choose `ours`, `theirs`, current, or incoming changes. Produce the conceptually correct result while preserving compatible behavior, invariants, tests, documentation, configuration, security boundaries, provenance, and API contracts. When intentions are incompatible, make the smallest explicit design decision and document it in the pull request.

After resolving conflicts, review every affected file from the top, not only the conflict hunks. Run the relevant formatters, linters, tests, and builds, including headless and GUI checks when their code is affected. Then search the entire worktree for unresolved markers, excluding `.git`:

```sh
grep -RInE '^(<<<<<<<|=======|>>>>>>>)' --exclude-dir=.git .
```

If any marker or suspicious partial resolution remains, repeat the semantic resolution process from the top and rerun validation. A conflict is resolved only when the result is conceptually coherent and verified, not merely when Git accepts the file.

## Change discipline

Keep changes scoped, preserve repository conventions, update tests when behavior changes, and record validation and residual risk in the pull request.

## Repository-local Git worktrees

- Create or use a Git worktree only when the human operator explicitly authorizes it for the current task. Concurrency or a dirty checkout is not permission by itself.
- Put every authorized worktree at `<repository-root>/tmp/worktrees/<name>`; from the repository root, use `./tmp/worktrees/<name>`. Never place worktrees beside repositories or organization directories.
- Keep `tmp`, `temp`, `tmp/worktrees`, and `temp/worktrees` ignored in the repository-root `.gitignore`. Do not commit files from those directories.
- Relocate or remove a worktree only when the operator explicitly requests it. Before removal, preserve and publish intended changes, verify its commit is represented on the target branch, and confirm there are no tracked, untracked, ignored-sensitive, or in-use files that must survive. Remove it with `git worktree remove <path>` without `--force`; never delete a worktree directory with `rm`.
