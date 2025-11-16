.PHONY: build test clean install release help

# Default target
all: build

# Build the project
build:
	cargo build --release

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean

# Install globally (requires sudo)
install: build
	sudo cp target/release/shadowrecon /usr/local/bin/

# Run clippy lints
lint:
	cargo clippy -- -D warnings

# Format code
fmt:
	cargo fmt

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Build and run
run: build
	./target/release/shadowrecon --help

# Create release build
release:
	cargo build --release --target x86_64-unknown-linux-gnu
	cargo build --release --target x86_64-apple-darwin
	cargo build --release --target x86_64-pc-windows-msvc

# Development setup
dev-setup:
	rustup update
	rustup component add clippy rustfmt

# Help
help:
	@echo "Available targets:"
	@echo "  build      - Build the project in release mode"
	@echo "  test       - Run tests"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install binary globally (requires sudo)"
	@echo "  lint       - Run clippy lints"
	@echo "  fmt        - Format code"
	@echo "  fmt-check  - Check code formatting"
	@echo "  run        - Build and show help"
	@echo "  release    - Build for multiple platforms"
	@echo "  dev-setup  - Setup development environment"
	@echo "  help       - Show this help message"