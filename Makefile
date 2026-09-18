# Vigil AI — Root Makefile
# Targets: install, dev, test, init-db, seed, lint, typecheck

.PHONY: install dev test init-db seed lint typecheck help

# ── Paths ──────────────────────────────────────────────────────────────────────
BACKEND_DIR := backend
FRONTEND_DIR := frontend

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*##' Makefile | awk 'BEGIN {FS = ":.*##"}; {printf "  %-14s %s\n", $$1, $$2}'

install:  ## Install all backend and frontend dependencies
	cd $(BACKEND_DIR) && pip install -e ".[dev]"
	cd $(FRONTEND_DIR) && npm install

dev:  ## Start FastAPI (:8000) and Next.js (:3000) concurrently
	@echo "Starting Vigil AI development servers..."
	start /B cmd /C "cd $(BACKEND_DIR) && uvicorn vigil.api.main:app --reload --host 0.0.0.0 --port 8000"
	cd $(FRONTEND_DIR) && npm run dev

init-db:  ## Initialise the SQLite database and run all Alembic migrations
	cd $(BACKEND_DIR) && python scripts/init_db.py

seed:  ## Seed mock inbox with sample .eml fixtures
	cd $(BACKEND_DIR) && python scripts/seed_mock_inbox.py

test:  ## Run all backend tests with pytest
	cd $(BACKEND_DIR) && pytest tests/ -v

lint:  ## Run Ruff linter and Black formatter check
	cd $(BACKEND_DIR) && ruff check vigil/ && black --check vigil/

typecheck:  ## Run mypy type checking
	cd $(BACKEND_DIR) && mypy vigil/ --ignore-missing-imports
