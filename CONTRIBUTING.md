# Contributing to MCP Attest

👋 **Welcome to MCP Attest!**

Thank you for your interest in making MCP server identity and trust verification better. Every contribution — big or small — helps build a more secure AI agent ecosystem. We're excited to have you onboard.

## First Time Contributor?

Here are some great ways to get started:

- Search for issues labeled `good first issue`
- Add test coverage for edge cases
- Improve documentation or add examples
- Review open pull requests and share feedback
- Write a new identity verification method

We value quality over quantity — even a well-written bug report counts as a contribution!

## Need Help?

Have a question or ran into an issue?

- Open a [GitHub Issue](https://github.com/Carlos-Projects/mcp-attest/issues)
- Check existing issues first — your question may already be answered
- Include relevant details: Python version, OS, what you tried

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

---

💡 This project is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its principles.
