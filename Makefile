.PHONY: install test lint typecheck clean build

install:
	pip install -e ".[dev]"

test:
	python3 -m pytest tests/ -v --cov=src/mcp_attest

test-quick:
	python3 -m pytest tests/ -q --no-cov

lint:
	ruff check .

lint-fix:
	ruff check . --fix

typecheck:
	mypy src/mcp_attest/

clean:
	rm -rf dist/ build/ *.egg-info/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build: clean
	python3 -m build

all: lint typecheck test build
