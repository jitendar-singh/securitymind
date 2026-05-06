.PHONY: help install install-dev venv client server dev adk test unit-test coverage lint clean

PYTHON  ?= python3
VENV    ?= .venv
PIP     := $(VENV)/bin/pip
PY      := $(VENV)/bin/python
BEHAVE  := $(VENV)/bin/behave
PORT    ?= 5001

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# ---------- Setup ----------

venv: ## Create virtualenv
	$(PYTHON) -m venv $(VENV)

install: venv ## Install Python dependencies
	$(PIP) install -r requirements.txt

install-dev: install ## Install dev dependencies (behave)
	$(PIP) install behave

client: ## Install frontend dependencies
	cd client && npm install

# ---------- Run ----------

server: ## Start Flask backend (port 5001)
	$(PY) main.py

adk: ## Start ADK web UI
	$(VENV)/bin/adk web

dev: ## Start backend + frontend in parallel
	@echo "Starting backend on :$(PORT) and frontend on :5173"
	@$(PY) main.py & \
	cd client && npm run dev; \
	wait

# ---------- Test ----------

test: ## Run BDD e2e tests
	$(BEHAVE) tests/features/

unit-test: ## Run pytest unit tests
	$(PY) -m pytest tests/unit/ -v --tb=short

coverage: ## Run all tests with coverage
	$(PY) -m coverage run --source=main,secmind -m behave tests/features/ && \
	$(PY) -m coverage run -a --source=main,secmind -m pytest tests/unit/ -v && \
	$(PY) -m coverage report --show-missing

# ---------- Lint ----------

lint: ## Lint frontend
	cd client && npm run lint

# ---------- Clean ----------

clean: ## Remove build artifacts and caches
	rm -rf $(VENV) client/node_modules client/dist
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -not -path './.venv/*' -delete 2>/dev/null || true
