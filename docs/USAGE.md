# Usage Guide

Detailed usage guide for rustdoc-checker.

## Command Line Options

```
rustdoc-checker <PATH> [OPTIONS]

ARGS:
    <PATH>    Directory or file to check

OPTIONS:
    -m, --mode <MODE>    What to check: docs, lazy, both [default: both]
    -v, --verbose        Show files without issues
    --strict             Exit with code 1 if any issues found
    --exclude <DIRS>     Comma-separated directory names to exclude
    --check-private      Also check private items (not just pub)
    -h, --help           Print help
```

## Modes

### `--mode docs` (Missing Documentation)

Checks for completely missing documentation:

- Module-level `//!` comments
- Public functions, structs, enums, traits
- Type aliases, constants, statics

```bash
rustdoc-checker ./src --mode docs
```

### `--mode lazy` (Lazy Documentation)

Checks for incomplete documentation sections:

| Condition | Required Section |
|-----------|------------------|
| Function has 2+ parameters | `# Arguments` |
| Function returns non-unit | `# Returns` |
| Function returns `Result` | `# Errors` |
| Function is `unsafe` | `# Safety` |
| Function can panic | `# Panics` |

```bash
rustdoc-checker ./src --mode lazy
```

### `--mode both` (Default)

Checks for both missing and lazy documentation.

```bash
rustdoc-checker ./src --mode both
# or just:
rustdoc-checker ./src
```

## Panic Detection

The lazy docs checker detects functions that can panic and flags them if they lack a `# Panics` section. The following patterns are detected:

**Macros:**
- `panic!()`, `unreachable!()`, `todo!()`, `unimplemented!()`
- `assert!()`, `assert_eq!()`, `assert_ne!()`
- `debug_assert!()`, `debug_assert_eq!()`, `debug_assert_ne!()`

**Method calls:**
- `.unwrap()`, `.expect()`

**Expressions:**
- Array/slice indexing: `arr[idx]`
- Integer division: `a / b`
- Modulo: `a % b`

## Visibility Filtering

By default, only `pub` items are checked. Use `--check-private` to include private items:

```bash
# Public items only (default)
rustdoc-checker ./src

# Include private items
rustdoc-checker ./src --check-private
```

## Excluding Directories

Exclude specific directories (comma-separated, no spaces):

```bash
rustdoc-checker . --exclude tests,benches,examples
```

The following directories are always excluded:
- `target`
- `.git`
- `node_modules`
- `.cargo`

## CI Integration

Use `--strict` to exit with code 1 when issues are found:

```bash
rustdoc-checker ./src --strict
```

### GitHub Actions Example

```yaml
name: Documentation Check

on: [push, pull_request]

jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-action@stable

      - name: Install rustdoc-checker
        run: cargo install --path ./rustdoc-checker

      - name: Check documentation
        run: rustdoc-checker ./src --strict
```

## Output Format

Output is deterministic, sorted by file path then line number:

```
src/lib.rs
----------
  L   5 | missing_doc    | process: Missing documentation
  L  12 | missing_args   | parse: Has 3 params (a, b, c) but no # Arguments
  L  12 | missing_returns| parse: Returns value but no # Returns section
  L  45 | missing_errors | load: Returns Result but no # Errors section
  L  67 | missing_panics | divide: Function can panic but no # Panics section

============================================================
Files scanned: 8
Files with issues: 2
Total issues: 5

Breakdown by type:
  missing_doc   : 1
  missing_args  : 1
  missing_returns: 1
  missing_errors: 1
  missing_panics: 1
```

### Issue Types

| Code | Description |
|------|-------------|
| `missing_doc` | Item has no documentation |
| `missing_args` | Function docs lack `# Arguments` section |
| `missing_returns` | Function docs lack `# Returns` section |
| `missing_errors` | Function docs lack `# Errors` section |
| `missing_panics` | Function docs lack `# Panics` section |
| `missing_safety` | Unsafe function docs lack `# Safety` section |

## Common Use Cases

### Check a single file

```bash
rustdoc-checker ./src/lib.rs
```

### Check entire project

```bash
rustdoc-checker .
```

### Run in verbose mode

Show all files including those without issues:

```bash
rustdoc-checker ./src -v
```

### Pre-commit hook

```bash
#!/bin/bash
rustdoc-checker ./src --strict || exit 1
```
