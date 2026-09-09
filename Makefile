APP_NAME := http
BUILD_DIR := runtime/bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X 'main.Version=$(VERSION)' -X 'main.BuildTime=$(BUILD_TIME)'

.PHONY: all build-cli build-api build-consumer build-service tag clean test

help: ## Display this help message
	@echo "Available targets:"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

all: build-cli ## Build all components

build-cli: ## Build the CLI component
	@echo "Building CLI..."
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-cli ./cmd/cli

build-api: ## Build the API component
	@echo "Building API..."
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-api ./cmd/api

build-consumer: ## Build the Consumer component
	@echo "Building Consumer..."
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-consumer ./cmd/consumer

build-service: ## Build the Service component
	@echo "Building Service..."
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME)-service ./cmd/service

tag: ## Create an annotated release tag (usage: make tag TAG=v0.x.y)
	@if [ -z "$(TAG)" ]; then echo "Usage: make tag TAG=v0.x.y"; exit 1; fi
	@case "$(TAG)" in v[0-9]*) ;; *) echo "TAG must look like vX.Y.Z"; exit 1;; esac
	@if [ -n "$$(git status --porcelain)" ]; then echo "working tree not clean"; exit 1; fi
	git tag -a $(TAG) -m "Release $(TAG)"
	@echo "Created tag $(TAG). Push it with:  git push origin $(TAG)"
	@echo "The release workflow builds and publishes the GitHub Release."

test: ## Run all tests
	kue test --dir tests

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
