# Development Guide

## Prerequisites

Ensure the following dependencies are installed prior to local development:

* Git
* Go 1.27+
* GNU Make
* golangci-lint (Go code static analysis)
* govulncheck (Go vulnerability scanner)
* hadolint (Dockerfile linter)
* trivy (filesystem and vulnerability scanner)
* gitleaks (secrets scanner)

## Repository Initialization

1. **Clone the repository:**
   ```bash
   git clone https://github.com/underhax/mihomo-warp-proxy.git
   cd mihomo-warp-proxy
   ```

2. **Install Security and Quality Tooling:**
   Install required linters and scanners utilized in CI pipelines and local verification:
   * **golangci-lint:** [https://golangci-lint.run/docs/welcome/install/](https://golangci-lint.run/docs/welcome/install/)
   * **govulncheck:** `go install golang.org/x/vuln/cmd/govulncheck@latest`
   * **hadolint:** [https://github.com/hadolint/hadolint#install](https://github.com/hadolint/hadolint#install)
   * **trivy:** [https://trivy.dev/docs/latest/getting-started/](https://trivy.dev/docs/latest/getting-started/)
   * **gitleaks:** [https://github.com/gitleaks/gitleaks#installing](https://github.com/gitleaks/gitleaks#installing)

3. **Development Files Layout:**
   ```text
   ├── Dockerfile                     # Multi-stage scratch container build
   ├── Makefile                       # Validation, test, and linting targets
   ├── .golangci.yml                  # Strict Go linter configuration
   ├── go.mod                         # Go module definition
   ├── cmd/
   │   └── entrypoint/                # Container initialization supervisor and healthcheck engine
   ├── internal/
   │   ├── backup/                    # Atomic configuration backup and restore utilities
   │   ├── config/                    # Configuration loading, validation, and Docker secrets resolution
   │   ├── contract/                  # Centralized constants for parameters and log levels
   │   ├── fsutil/                    # Secure atomic file writer with directory synchronization
   │   ├── geo/                       # Geodata asset synchronization, checksums, and SSRF prevention
   │   ├── health/                    # In-process health checking via local proxy probes
   │   ├── logging/                   # Structured, level-filtered logging handler
   │   ├── mihomo/                    # AST-based YAML patching preserving user rules and custom proxies
   │   ├── validate/                  # Path traversal, IP restrictions, and AmneziaWG validation
   │   ├── warp/                      # Cloudflare WARP device token parsing and reserved bytes extraction
   │   └── wgcf/                      # WGCF subprocess management, profile generation, and license handling
   ├── docker-compose.dev.yaml        # Local development build and debug manifest
   └── .env.example                   # Environment configuration template
   ```

## Code Validation & Testing

All validation steps are centralized in the [`Makefile`](Makefile).

1. **Code Formatting, Linting & Unit Tests:**
   Validate Go formatting (`gofmt -s`), execute `golangci-lint`, verify compilation, and run race-enabled unit tests:
   ```bash
   make check
   make test
   ```

2. **Vulnerability & Container Scanning:**
   Execute Go vulnerability analysis, secrets detection, and filesystem security scanning:
   ```bash
   make vulncheck
   make secrets-scan
   make trivy
   make docker-lint
   ```

3. **Code Coverage:**
   Execute unit tests with the race detector enabled and generate a statement coverage report:
   ```bash
   make coverage
   ```
   To remove generated coverage artifacts:
   ```bash
   make clean
   ```

4. **Complete Project Verification:**
   Prior to committing changes or submitting a pull request, execute the complete validation suite:
   ```bash
   make verify
   ```

## Build & Local Development Workflow

1. **Compile the Go entrypoint locally:**
   ```bash
   CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /dev/null ./cmd/entrypoint
   ```

2. **Build the container image using Docker Compose:**
   ```bash
   docker compose -f docker-compose.dev.yaml build --progress=plain
   ```

   To rebuild without utilizing cached layers:
   ```bash
   docker compose -f docker-compose.dev.yaml build --progress=plain --no-cache
   ```

3. **Start the local development stack:**
   ```bash
   docker compose -f docker-compose.dev.yaml up
   ```

## Makefile Targets Reference

| Target | Description |
| --- | --- |
| `make check` | Validates formatting (`gofmt -s`), executes `golangci-lint`, and verifies compilation. |
| `make test` | Runs the Go unit test suite with data race detection enabled (`-race`). |
| `make coverage` | Generates a function-level statement coverage report (`coverage.out`). |
| `make vulncheck` | Analyzes Go source code and dependencies for known vulnerabilities via `govulncheck`. |
| `make secrets-scan` | Scans source code and repository files for leaked secrets and credentials using `gitleaks`. |
| `make docker-lint` | Lints the multi-stage `Dockerfile` using `hadolint`. |
| `make trivy` | Scans the filesystem for `CRITICAL` and `HIGH` severity vulnerabilities using `trivy`. |
| `make verify` | Sequentially executes `check`, `test`, `vulncheck`, `trivy`, `docker-lint`, and `secrets-scan`. |
| `make clean` | Removes generated test artifacts and coverage profiles. |
