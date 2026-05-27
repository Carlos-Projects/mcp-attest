# Changelog

All notable changes to MCP Attest will be documented in this file.

## [0.1.0] - 2026-05-26

### Added

- Initial release
- Identity verification via TLS certificates, cryptographic signatures (RSA-2048 SHA-256), and DIDs (did:web, did:key)
- Integrity attestation with SHA-256 manifest generation and capability fingerprinting
- Permission auditing with least privilege scoring
- Trust score calculation (0–100) with configurable weights
- Revocation checking against configurable trust lists
- MCPGuard policy generation
- Reporters: Console (Rich), JSON, SARIF
- Taxonomy integration via `mcp-taxonomy` (PyPI)
- SSRF protection with private IP blocking
- Input validation with JSON size/depth limits
- 274 tests with 99% coverage
- Ruff linting (0 errors) and mypy strict type checking (0 errors)
