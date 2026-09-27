# Contributing to Sentinel

Thanks for your interest in contributing. This document covers how changes land on `main`.

## Getting Started

1. Fork and clone the repository
2. Follow the quick start in [README.md](README.md) to build the images
3. Read [docs/codebase-map.md](docs/codebase-map.md) for the module map

## Making Changes

1. Create a feature branch from `main`
2. Make your changes. Prefer editing existing files over creating new ones
3. Commit with [conventional commit](https://www.conventionalcommits.org/) messages:
   - `feat:` new features
   - `fix:` bug fixes
   - `docs:` documentation changes
   - `refactor:` code restructuring without behaviour change
4. Open a pull request against `main`

## Guidelines

- **Security first.** Every change should consider the threat model. If you are unsure whether a change could weaken a boundary, open an issue before submitting a pull request
- **No secrets in code.** Never commit API keys, tokens, or credentials. Use Podman secrets
- **The air gap stays intact.** The worker LLM must not gain a route to the internet. Changes that touch networking need a careful look
- **Keep it simple.** The security pipeline is already complex. Extra complexity needs a reason

## Reporting Issues

Use GitHub Issues for bug reports (with reproduction steps) and feature requests. For vulnerabilities, see [SECURITY.md](SECURITY.md). Do not open a public issue for a security report.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
