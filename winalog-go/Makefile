.PHONY: build test lint clean install run deps fmt vet

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOLINT=$(GOCMD) vet
GOFMT=$(GOCMD) fmt
GOMOD=$(GOCMD) mod

# Binary name
BINARY_NAME=winalog
BINARY_WIN=$(BINARY_NAME).exe

# Build directories
BUILD_DIR=build
BUILD_WIN=$(BUILD_DIR)/windows
BUILD_LINUX=$(BUILD_DIR)/linux
BUILD_MAC=$(BUILD_DIR)/darwin

# Version info
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# Main targets
all: test lint build

## build: Build for current platform
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p internal/api/_statich
	@cp -r internal/gui/dist/* internal/api/_statich/ 2>/dev/null || true
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) ./cmd/winalog

## build-windows: Build for Windows
build-windows:
	@echo "Building $(BINARY_WIN) for Windows..."
	@mkdir -p $(BUILD_WIN)
	@mkdir -p internal/api/_statich
	@cp -r internal/gui/dist/* internal/api/_statich/ 2>/dev/null || true
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_WIN)/$(BINARY_WIN) ./cmd/winalog

## build-linux: Build for Linux
build-linux:
	@echo "Building $(BINARY_NAME) for Linux..."
	@mkdir -p $(BUILD_LINUX)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_LINUX)/$(BINARY_NAME) ./cmd/winalog

## build-all: Build for all platforms
build-all: build-windows build-linux build-darwin

## build-darwin: Build for macOS
build-darwin:
	@echo "Building $(BINARY_NAME) for macOS..."
	@mkdir -p $(BUILD_MAC)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_MAC)/$(BINARY_NAME) ./cmd/winalog

## test: Run unit tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -cover ./...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## lint: Run linters
lint:
	@echo "Running linters..."
	$(GOLINT) ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "Warning: golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## tidy: Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME) $(BINARY_WIN)
	rm -f coverage.out coverage.html

## install: Install binary
install: build
	@echo "Installing $(BINARY_NAME)..."
	$(GOCMD) install $(LDFLAGS) ./cmd/winalog

## run: Run the application
run:
	@echo "Running $(BINARY_NAME)..."
	$(GOCMD) run ./cmd/winalog

## init: Initialize project (first time setup)
init:
	@echo "Initializing project..."
	$(GOMOD) init github.com/kkkdddd-start/winalog-go
	$(GOMOD) tidy

## verify: Verify dependencies
verify:
	$(GOMOD) verify

## help: Show this help
help:
	@echo "WinLogAnalyzer-Go Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
