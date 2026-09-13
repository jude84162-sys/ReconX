# Contributing to ReconX v2

Thanks for your interest in contributing! 🎉

## Prerequisites

- **Rust 1.75+** (install via [rustup](https://rustup.rs))
- **Git**
- (Optional) **Docker** for container builds
- (Optional) API keys for integration testing

## Local Setup

    git clone https://github.com/jude84162-sys/ReconX.git
    cd ReconX/reconx-v2
    cargo build
    cargo test --all
    cargo run -- email test@example.com --self

## Development Workflow

### 1. Create a branch

    git checkout main
    git pull origin main
    git checkout -b feat/my-feature

Branch naming:

- `feat/<name>` — new feature
- `fix/<name>` — bug fix
- `docs/<name>` — documentation
- `refactor/<name>` — code refactor
- `chore/<name>` — maintenance

### 2. Make your changes

Follow the existing code style. All public items need doc comments (`///`).

### 3. Run all checks

    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test --all
    cargo build --release

**All 4 must pass before pushing.**

### 4. Commit

Use [Conventional Commits](https://www.conventionalcommits.org/):

    feat(v2): add phone number recon
    fix(v2): handle empty email in CLI
    docs(v2): clarify HIBP API key setup
    chore(v2): bump tokio to 1.36

### 5. Push and open a PR

    git push origin feat/my-feature

Then open a PR on GitHub.

## Code Standards

### Rust

- **No `unwrap()`** outside tests — use `?` or explicit error handling
- **No `panic!()`** in library code
- **No blocking calls** inside `async` (use `tokio::time::sleep`)
- **Doc comments** on all public items
- **Unit tests** for every new public function

### Error Handling

Use `ReconError` (in `reconx-core`):

    use reconx_core::{ReconError, Result};

    fn parse_email(s: &str) -> Result<String> {
        if s.is_empty() {
            return Err(ReconError::InvalidEmail(s.to_string()));
        }
        Ok(s.to_lowercase())
    }

### Async

Prefer `tokio::join!` for parallel I/O:

    let (a, b, c) = tokio::join!(
        fetch_a(),
        fetch_b(),
        fetch_c(),
    );

## Testing

- **Unit tests**: `#[cfg(test)] mod tests { ... }`
- **Integration tests**: `tests/` directory
- **Mock HTTP**: use [`mockito`](https://docs.rs/mockito)
- **Coverage**: `cargo tarpaulin --out Html`

## Adding a new API

1. Create `crates/reconx-breach/src/<name>.rs`
2. Expose `pub async fn check(email: &str, timeout: u64) -> Result<...>`
3. Wire into `aggregator.rs`
4. Add confidence score
5. Add unit tests with `mockito`
6. Update README features table

## Adding a new crate

1. Create `crates/reconx-<name>/` with `Cargo.toml` + `src/lib.rs`
2. Add to `[workspace] members` in root `Cargo.toml`
3. Implement `ReconModule` trait from `reconx-core`
4. Wire into `reconx-cli` as a new subcommand
5. Add integration test

## Adding a new site to the username scanner (future)

Add an entry to `reconx-v2/data/sites.yaml`:

    - name: ExampleSite
      url_template: "https://example.com/{username}"
      exists_indicators:
        - status_code: 200
        - not_contains: "User not found"
      confidence_boosters:
        - "div.profile"
      rate_limit: 60

## PR Checklist

Before opening a PR:

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test --all` passes
- [ ] `cargo build --release` succeeds
- [ ] New public items have doc comments
- [ ] CHANGELOG.md updated (if user-facing)
- [ ] README.md updated (if new feature)
- [ ] No `.env` or secrets committed
- [ ] PR description explains the change

## Code Review

All PRs require:

1. **Green CI** (fmt, clippy, test, build)
2. **At least 1 approval** (from maintainer)
3. **No merge conflicts** with `main`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Open a GitHub Discussion or Issue.

Thanks for contributing! 💪
