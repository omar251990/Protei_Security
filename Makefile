.PHONY: all build clean test docker-build docker-up docker-down install-deps

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build output directory
BUILD_DIR=bin

# Binary names
MANAGER_BINARY=$(BUILD_DIR)/protei-manager
SCANNER_BINARY=$(BUILD_DIR)/protei-scanner
LINUX_AGENT_BINARY=$(BUILD_DIR)/protei-agent-linux
WINDOWS_AGENT_BINARY=$(BUILD_DIR)/protei-agent-windows.exe
DB_SCANNER_BINARY=$(BUILD_DIR)/protei-db-scanner
NETMON_BINARY=$(BUILD_DIR)/protei-netmon
CVE_SYNC_BINARY=$(BUILD_DIR)/protei-cve-sync

# Build flags
LDFLAGS=-ldflags "-s -w"

all: build

build: build-manager build-scanner build-agent-linux build-agent-windows

build-manager:
	@echo "Building Central Manager..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(MANAGER_BINARY) ./cmd/manager

build-scanner:
	@echo "Building Network Scanner..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(SCANNER_BINARY) ./cmd/scanner

build-agent-linux:
	@echo "Building Linux Agent..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(LINUX_AGENT_BINARY) ./cmd/agent-linux

build-agent-windows:
	@echo "Building Windows Agent..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(WINDOWS_AGENT_BINARY) ./cmd/agent-windows

build-db-scanner:
	@echo "Building Database Scanner..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(DB_SCANNER_BINARY) ./cmd/db-scanner

build-netmon:
	@echo "Building Network Monitor..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(NETMON_BINARY) ./cmd/netmon

build-cve-sync:
	@echo "Building CVE Sync..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(CVE_SYNC_BINARY) ./cmd/cve-sync

clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

install-deps:
	@echo "Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) verify

docker-build:
	@echo "Building Docker images..."
	docker-compose build

docker-up:
	@echo "Starting Docker containers..."
	docker-compose up -d

docker-down:
	@echo "Stopping Docker containers..."
	docker-compose down

docker-logs:
	docker-compose logs -f

# Database migrations
migrate-up:
	@echo "Running database migrations..."
	# Add migration tool here

migrate-down:
	@echo "Rolling back database migrations..."
	# Add migration tool here

# Development helpers
dev-manager:
	@echo "Running manager in development mode..."
	$(GOCMD) run ./cmd/manager

dev-agent-linux:
	@echo "Running Linux agent in development mode..."
	$(GOCMD) run ./cmd/agent-linux

# Generate swagger docs
swagger:
	@echo "Generating Swagger documentation..."
	swag init -g cmd/manager/main.go -o docs/swagger

# Install tools
install-tools:
	@echo "Installing development tools..."
	$(GOGET) -u github.com/swaggo/swag/cmd/swag
	$(GOGET) -u github.com/golangci/golangci-lint/cmd/golangci-lint

# Linting
lint:
	@echo "Running linter..."
	golangci-lint run ./...

# Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# Security scanning
security-scan:
	@echo "Running security scan..."
	gosec ./...

# Generate certificates for development
gen-certs:
	@echo "Generating development certificates..."
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
		-days 365 -nodes -subj "/CN=protei-manager"
	openssl req -x509 -newkey rsa:4096 -keyout certs/client.key -out certs/client.crt \
		-days 365 -nodes -subj "/CN=protei-agent"
	openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.crt \
		-days 365 -nodes -subj "/CN=protei-ca"

# Create default admin user
create-admin:
	@echo "Creating default admin user..."
	$(GOCMD) run scripts/create_admin.go

.DEFAULT_GOAL := build
