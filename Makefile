SHELL := /bin/sh
.DEFAULT_GOAL := help

.PHONY: help install check test start migrate migrate-container keys compose-config image up up-cache down logs clean

help: ## Show available commands.
	@awk 'BEGIN {FS = ":.*## "; printf "AuthMe development commands\n\n"} /^[a-zA-Z_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install the exact dependency tree from package-lock.json.
	npm ci

check: ## Run static and policy checks.
	npm run check

test: ## Run the complete test suite.
	npm test

start: ## Start AuthMe with the current environment.
	npm start

migrate: ## Apply pending database migrations.
	npm run db:migrate

migrate-container: ## Apply migrations using the production container configuration.
	docker compose --env-file .env run --rm authme npm run db:migrate

keys: ## Generate a local development signing-key set under .local/jwks.
	mkdir -p .local/jwks
	AUTHME_JWKS_DIR="$${AUTHME_JWKS_DIR:-.local/jwks}" npm run keys:generate

compose-config: ## Validate the resolved Compose configuration (requires .env).
	docker compose --env-file .env config --quiet

image: ## Build the production runtime image.
	docker compose --env-file .env build --pull authme

up: ## Start AuthMe and PostgreSQL.
	docker compose --env-file .env up --build -d authme

up-cache: ## Start AuthMe, PostgreSQL, and optional Redis.
	docker compose --env-file .env --profile cache up --build -d

down: ## Stop the Compose stack without deleting persistent data.
	docker compose --env-file .env down

logs: ## Follow application logs.
	docker compose --env-file .env logs -f authme

clean: ## Remove local generated test/build artifacts only.
	rm -rf coverage .nyc_output
