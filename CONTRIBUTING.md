# Contributing to MCP Attest

Thank you for your interest in contributing! This project is part of the MCP Security ecosystem.

## Getting Started

```bash
pip install -e ".[dev]"
```

## Code Standards

- Python 3.11+ with full type hints
- `ruff check .` must pass with zero errors
- `pytest` must pass with >80% coverage
- Follow [AGENTS.md](https://github.com/Carlos-Projects/AGENTS.md) workspace conventions

## Running Tests

```bash
pytest
pytest --cov=src/mcp_attest --cov-report=term-missing
```

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Write tests for new functionality
4. Ensure `ruff check .` and `pytest` pass
5. Submit a PR with a clear description of changes

## Security Issues

Report security vulnerabilities via the [SECURITY.md](SECURITY.md) process. Do not open public issues for security bugs.
