# Contributing to dropctl

Thank you for your interest in contributing!

## Code of Conduct

Be respectful, inclusive, and constructive. We welcome contributors from all backgrounds.

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists
2. Open a new issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details

### Suggesting Features

1. Open a discussion first
2. Explain the use case
3. Propose a solution

### Pull Requests

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add tests if applicable
5. Ensure tests pass: `cargo test`
6. Format code: `cargo fmt`
7. Lint: `cargo clippy`
8. Push and open a PR

## Development Setup

```bash
# Clone
git clone https://github.com/dablon/dropctl.git
cd dropctl

# Build
cargo build --release

# Test
cargo test

# Format
cargo fmt --check
cargo fmt
```

## Style Guide

- Follow standard Rust conventions
- Use `cargo fmt` for formatting
- Run `cargo clippy` before submitting
- Write tests for new features

## Commit Messages

Use conventional commits:
- `feat: add new feature`
- `fix: resolve bug`
- `docs: update documentation`
- `test: add tests`
- `refactor: restructure code`

## Review Process

1. Automated checks must pass
2. At least one maintainer review required
3. Address feedback promptly
