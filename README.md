# rustdoc-checker

Lint Rust code for missing/lazy documentation. Designed for CI enforcement on LLM-generated codebases.

## Build

```bash
cargo build --release
# Binary at: target/release/rustdoc-checker
```

## Installation

```bash
# Install to ~/.cargo/bin (must be in PATH)
cargo install --path .

# Verify installation
rustdoc-checker --help
```

If `~/.cargo/bin` is not in your PATH, add it:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.cargo/bin:$PATH"
```

## Usage

```bash
# Check directory (public items only, both missing + lazy docs)
rustdoc-checker ./src

# Check single file
rustdoc-checker ./src/lib.rs

# Only missing docs (no lazy checks)
rustdoc-checker ./src --mode docs

# Only lazy docs (no missing checks)
rustdoc-checker ./src --mode lazy

# Include private items
rustdoc-checker ./src --check-private

# CI mode (exit 1 on any issues)
rustdoc-checker ./src --strict

# Exclude directories
rustdoc-checker . --exclude tests,benches,examples

# Verbose (show OK files)
rustdoc-checker ./src -v
```

## What It Checks

**Missing docs (`--mode docs`):**
- Module-level `//!` comments
- Public functions, structs, enums, traits, type aliases, consts, statics

**Lazy docs (`--mode lazy`):**
- `# Arguments` section required if function has 2+ parameters
- `# Returns` section required if function returns non-unit
- `# Errors` section required if function returns `Result`
- `# Safety` section required for `unsafe fn`
- `# Panics` section required if function can panic (uses `panic!`, `unwrap()`, `expect()`, `assert!`, array indexing, division, etc.)

## Output Format

Deterministic, sorted by file path then line number:

```
src/lib.rs
----------
  L   5 | missing_doc    | process: Missing documentation
  L  12 | missing_args   | parse_config: Has 3 params (path, opts, env) but no # Arguments section
  L  12 | missing_returns| parse_config: Returns value but no # Returns section
  L  45 | missing_errors | load_file: Returns Result but no # Errors section

============================================================
Files scanned: 8
Files with issues: 2
Total issues: 4

Breakdown by type:
  missing_doc   : 1
  missing_args  : 1
  missing_returns: 1
  missing_errors: 1
```

## CI Integration

```yaml
# GitHub Actions example
- name: Check documentation
  run: |
    cargo install --path ./rustdoc-checker
    rustdoc-checker ./src --strict
```

## Why Not Just `#![deny(missing_docs)]`?

That catches missing docs but not **lazy** docs. LLM agents often generate one-liner docstrings that technically exist but don't document parameters, returns, or error conditions. This tool catches both.
