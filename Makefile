# Makefile for sh-keyring
#
# Tests are written in pytest (see tests/) and exercise the bash library
# sh-keyring.shlib. They are run through `uv`, which fetches pytest into an
# ephemeral environment, so no manual virtualenv setup is required.

UV ?= uv
PYTEST ?= $(UV) run --with pytest pytest
TESTS ?= tests

.DEFAULT_GOAL := test

.PHONY: test
test: ## Run the test suite
	$(PYTEST) $(TESTS)

.PHONY: test-verbose
test-verbose: ## Run the test suite with verbose output
	$(PYTEST) -v $(TESTS)

.PHONY: watch
watch: ## Re-run tests on file changes (requires pytest-watch)
	$(UV) run --with pytest --with pytest-watch ptw $(TESTS)

.PHONY: coverage
coverage: ## Run tests with a coverage report
	$(UV) run --with pytest --with pytest-cov pytest --cov=. $(TESTS)

.PHONY: clean
clean: ## Remove test and Python caches
	rm -rf .pytest_cache .ruff_cache .mypy_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'