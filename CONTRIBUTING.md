# Contributing to ShadowRecon

Thank you for your interest in contributing to ShadowRecon! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Respect different viewpoints and experiences

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists
2. Create a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Rust version)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the use case and benefits
3. Discuss implementation approach if possible

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with clear commits
4. Test your changes thoroughly
5. Update documentation if needed
6. Submit a pull request with a clear description

### Coding Standards

- Follow Rust conventions (`cargo fmt`)
- Run `cargo clippy` and fix warnings
- Add tests for new features
- Document public APIs
- Keep commits focused and atomic

### Testing

```bash
# Run tests
cargo test

# Check formatting
cargo fmt --check

# Run linter
cargo clippy -- -D warnings

# Build release
cargo build --release
```

## Development Setup

1. Clone the repository
2. Install Rust (1.70+)
3. Build the project: `cargo build`
4. Run tests: `cargo test`

## Areas for Contribution

- OS fingerprinting improvements
- Additional scan types
- Performance optimizations
- Documentation improvements
- Bug fixes
- Test coverage

Thank you for contributing!
