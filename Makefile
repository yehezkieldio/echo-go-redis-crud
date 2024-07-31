# Load the environment variables from .env file
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Define variables for Docker Compose
DOCKER_COMPOSE_FILE=docker/infrastructure/compose.yml

# Targets
.PHONY: infra:up infra:down

infra:up:
	docker compose --file $(DOCKER_COMPOSE_FILE) --env-file .env up -d

infra:down:
	docker compose --file $(DOCKER_COMPOSE_FILE) --env-file .env down
