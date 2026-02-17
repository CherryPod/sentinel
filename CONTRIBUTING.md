# Contributing to Sentinel

Thanks for your interest in contributing. This document covers the development workflow and guidelines.

## Getting Started

1. Fork and clone the repository
2. Set up the development environment (see [docs/deployment.md](docs/deployment.md))
3. Run the test suite to verify your setup:
   ```bash
   # Python tests
   .venv/bin/pytest tests/ -v

   # Rust sidecar tests
   cargo test --manifest-path sidecar/Cargo.toml
   ```
4. Read [docs/codebase-map.md](docs/codebase-map.md) for an overview of the codebase structure

## Development Workflow

### Making Changes

1. Create a feature branch from `main`
2. Make your changes — prefer editing existing files over creating new ones
3. Write tests for new functionality
4. Run the full test suite and ensure all tests pass
5. Commit with [conventional commit](https://www.conventionalcommits.org/) messages:
   - `feat:` new features
   - `fix:` bug fixes
   - `docs:` documentation changes
   - `test:` test additions or fixes
   - `refactor:` code restructuring without behaviour change
6. Open a pull request against `main`

### Running Tests

```bash
# Python tests (requires Python 3.12 + dependencies from pyproject.toml)
.venv/bin/pytest tests/ -v

# Rust sidecar tests (requires Rust toolchain + wasm32-wasip1 target)
cargo test --manifest-path sidecar/Cargo.toml

# Quick check (Python only, stop on first failure)
.venv/bin/pytest tests/ -x -q
```

The test suite mocks all external services (Ollama, Claude API, Prompt Guard, CodeShield). No GPU, API keys, or running containers are needed.

Environment variables for CI/testing:
- `SENTINEL_PROMPT_GUARD_ENABLED=false` — skip Prompt Guard
- `SENTINEL_REQUIRE_CODESHIELD=false` — skip CodeShield
- `SENTINEL_PIN_REQUIRED=false` — skip PIN authentication

### Building Containers

```bash
# Build the controller + UI container
podman build \
  --secret id=hf_token,src=./secrets/hf_token.txt \
  -t sentinel:latest \
  -f container/Containerfile .

# Start the stack
podman compose up -d
```

See [docs/deployment.md](docs/deployment.md) for the full build procedure and common gotchas.

## Guidelines

- **Security first** — Sentinel is a security project. Every change should consider the threat model. If you're unsure whether a change could weaken security, open an issue to discuss before submitting a PR
- **Test coverage** — all new security-relevant code must have tests. The current suite has 1006 Python tests + 41 Rust tests
- **No secrets in code** — never commit API keys, tokens, or credentials. Use Podman secrets
- **Air gap is sacred** — the worker LLM must never have internet access. Any change that touches networking should be reviewed carefully
- **Keep it simple** — avoid over-engineering. The security pipeline is already complex; additional complexity should be justified

## Reporting Issues

Use GitHub Issues for:
- Bug reports (include reproduction steps and relevant logs)
- Feature requests
- Security-related questions (for vulnerabilities, see [SECURITY.md](SECURITY.md))

## Code of Conduct

Be respectful and constructive. We're building security tools — thoroughness and caution are valued over speed.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
