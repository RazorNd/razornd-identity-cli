# Repository guidance

- This is a single Rust 2024 binary crate; the executable starts in `src/main.rs`. There are no workspace members or repository-specific build/test scripts.
- From the repository root, use `cargo fmt -- --check`, `cargo check`, `cargo test`, and `cargo clippy -- -D warnings` for focused verification.
- `target/` is generated build output and is ignored; do not commit it.
- Prefer IDEA MCP for code search, navigation, and reading source files, including dependency sources, when available. Use shell-based inspection only when IDEA tools cannot access the target. For changed Rust code, use `reformat_file` and `lint_files` when available; use `build_project` for IDE compilation diagnostics and Cargo commands for build/test verification.

## Commit messages

- Follow Conventional Commits: `type(scope): description`; scope is optional. Use types such as `feat`, `fix`, `docs`, `refactor`, `test`, and `chore`, not bracketed labels.
- Keep the subject concise (ideally at most 72 characters), imperative, and without a trailing period.
- Optionally add one relevant emoji after the colon; never replace the commit type.
- For non-trivial changes, separate the subject and body with a blank line. Summarize changes and relevant reasoning; omit the body for trivial changes.
