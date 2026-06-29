.PHONY: build test run clean help coverage fmt lint

help:
	@echo "Zero-Trust Authentication System - Build Commands"
	@echo ""
	@echo "Available targets:"
	@echo "  build       - Build the project"
	@echo "  test        - Run all tests"
	@echo "  test-unit   - Run unit tests only"
	@echo "  test-int    - Run integration tests only"
	@echo "  coverage    - Generate coverage report"
	@echo "  run         - Run the interactive demo"
	@echo "  fmt         - Format code"
	@echo "  clean       - Remove build artifacts"
	@echo "  deps        - Download dependencies"

build:
	@echo "[*] Building zero-trust-auth..."
	go build -o bin/zero-trust-auth main.go

run: build
	@echo "[*] Running zero-trust-auth demo..."
	./bin/zero-trust-auth

test:
	@echo "[*] Running all tests..."
	go test ./... -v -race

test-unit:
	@echo "[*] Running unit tests..."
	go test ./ca -v

test-int:
	@echo "[*] Running integration tests..."
	go test . -v -run "^Test"

coverage:
	@echo "[*] Generating coverage report..."
	go test ./... -cover -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "[+] Coverage report generated: coverage.html"

fmt:
	@echo "[*] Formatting code..."
	go fmt ./...
	@echo "[+] Code formatted"

lint:
	@echo "[*] Running linter..."
	golint ./...

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	@echo "[+] Clean complete"

deps:
	@echo "[*] Downloading dependencies..."
	go mod download
	go mod verify
	@echo "[+] Dependencies verified"
