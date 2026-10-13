PY     ?= .venv/bin/python
MODEL  ?= llama3.2:3b
ALERTS ?= examples/flowguard_alerts.jsonl.gz
export PYTHONPATH := src

.DEFAULT_GOAL := help
.PHONY: help install incidents triage evaluate test lint format clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}'

install: ## Create .venv and install AlertLens with dev tools
	python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

incidents: ## Correlate the sample alerts into incidents
	$(PY) -m alertlens incidents $(ALERTS)

triage: ## Hybrid triage of the 15 largest incidents -> runtime/triage.md (needs Ollama)
	$(PY) -m alertlens triage $(ALERTS) --mode hybrid --model $(MODEL) --limit 15

evaluate: ## Rules vs LLM vs hybrid against ground truth -> reports/ (~1 h on a laptop CPU)
	$(PY) -m alertlens evaluate $(ALERTS) --model $(MODEL)

test: ## Run the test suite (no LLM needed)
	$(PY) -m pytest --cov --cov-report=term-missing

lint: ## Lint and check formatting
	$(PY) -m ruff check src tests
	$(PY) -m ruff format --check src tests

format: ## Auto-format the code
	$(PY) -m ruff check --fix src tests
	$(PY) -m ruff format src tests

clean: ## Remove caches and runtime output
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov runtime
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
