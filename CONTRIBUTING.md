# Contributing to Sentinel

Thanks for your interest in contributing. This document covers the development workflow and guidelines.

## Getting Started

1. Fork and clone the repository
2. Set up the development environment (see [docs/deployment.md](docs/deployment.md))
3. Run the test suite to verify your setup:
   ```bash
   podman exec sentinel-controller pytest /app/tests/ -v
   ```

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
# In-container tests (recommended — matches CI environment)
podman exec sentinel-controller pytest /app/tests/ -v

# Local tests (requires Python 3.12 + dependencies)
PYTHONPATH=controller .venv/bin/python -m pytest controller/tests/ -v
```

### Rebuilding After Code Changes

The controller requires a manual build (Prompt Guard model needs a HuggingFace token):

```bash
podman build \
  --secret id=hf_token,src=$HOME/.secrets/hf_token.txt \
  -t sentinel-controller:latest \
  -t sentinel_sentinel-controller:latest \
  -f controller/Dockerfile controller/

podman stop sentinel-ui sentinel-controller sentinel-qwen
podman rm sentinel-ui sentinel-controller sentinel-qwen
podman compose up -d --force-recreate
```

See [docs/deployment.md](docs/deployment.md) for the full rebuild procedure and common gotchas.

## Guidelines

- **Security first** — Sentinel is a security project. Every change should consider the threat model. If you're unsure whether a change could weaken security, open an issue to discuss before submitting a PR
- **Test coverage** — all new security-relevant code must have tests. The current suite has 435 unit tests
- **No secrets in code** — never commit API keys, tokens, or credentials. Use Podman secrets
- **Air gap is sacred** — `sentinel-qwen` must never have internet access. Any change that touches networking should be reviewed carefully
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
