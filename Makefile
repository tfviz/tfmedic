.DEFAULT_GOAL := help
PY := python3
PKG := tfmedic

.PHONY: help install dev lint format typecheck test cov build clean demo

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Install the package
	$(PY) -m pip install .

dev: ## Install with development extras, editable
	$(PY) -m pip install -e ".[dev]"

lint: ## Run ruff
	ruff check $(PKG) tests

format: ## Auto-format and fix imports
	ruff format $(PKG) tests
	ruff check --fix $(PKG) tests

typecheck: ## Run mypy in strict mode
	mypy $(PKG)

test: ## Run the test suite
	pytest

cov: ## Run tests with coverage
	pytest --cov=$(PKG) --cov-report=term-missing

build: ## Build wheel and sdist
	$(PY) -m build

clean: ## Remove build and cache artefacts
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

demo: ## Run the golden demo scenario against the configured account
	tfmedic "Diagnose why the web-api container is crashing on instance $(INSTANCE)" --verbose
