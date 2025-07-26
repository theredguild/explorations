# DevSec Audit 🔍

A comprehensive security auditor for development environments, inspired by Lynis but focused on DevSecOps practices. DevSec Audit scans your development projects for security misconfigurations, vulnerabilities, and best practice violations.

## Features

### 🔧 **Git Security Module**
- Git configuration analysis (global, local, system)
- Dangerous git aliases and hooks detection
- SSH key security assessment
- Credential exposure in git URLs
- Core settings validation (editor, pager)

### 🐳 **Docker Security Module**
- Dockerfile security best practices
- Container privilege analysis
- Dangerous volume mounts detection
- DevContainer configuration review
- Docker Compose security assessment

### 🎯 **VS Code Security Module**
- Extension security analysis
- Dangerous settings detection
- Automated task security review
- Launch configuration validation
- Workspace trust assessment

### 🔐 **Secrets Scanner Module**
- Exposed sensitive files detection
- Environment files and configuration analysis
- Private key and certificate exposure
- .gitignore coverage validation
- Lockfile tampering detection

### ⚒️ **Foundry Security Module**
- FFI (Foreign Function Interface) usage detection
- Dangerous filesystem permissions
- Test file security analysis
- Foundry.toml configuration validation

## Installation

### 🚀 **Recommended: Using uv (Secure & Fast)**
```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and setup
git clone <repository-url>
cd devsec-audit
just setup    # Sets up everything automatically
```

### 🛠️ **Using Just (Task Runner)**
```bash
# Install just if you don't have it
curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/bin

# Quick commands
just setup     # Full development setup
just scan      # Quick scan current directory  
just demo      # Run demonstration
just --list    # See all available commands
```

### 🐳 **Using Docker (Completely Isolated)**
```bash
# Build the container
docker build -t devsec-audit .

# Scan a project
docker run --rm -v /path/to/project:/audit devsec-audit --target /audit
```

### 📦 **Traditional pip (Less Secure)**
```bash
git clone <repository-url>
cd devsec-audit
pip install -e ".[dev,test]"
```

## Quick Start

### Basic Scan
```bash
# Using Just (recommended)
just scan                    # Quick scan current directory
just scan-target /path/to/project  # Scan specific directory
just report                  # Generate HTML report

# Using uv directly
uv run python -m core.cli    # Scan current directory
uv run python -m core.cli --target /path/to/project

# Using Docker (completely isolated)
docker run --rm -v $(pwd):/audit devsec-audit --target /audit
```

### Module-Specific Scans
```bash
# Using Just
just run --modules git,docker        # Scan only Git and Docker
just run --quick                     # Quick scan (essential modules only)

# Using uv
uv run python -m core.cli --modules git,docker
uv run python -m core.cli --quick
```

### Output Formats
```bash
# Generate HTML report
just run --format html --output security-report.html
uv run python -m core.cli --format html --output security-report.html

# Generate JSON report  
just run --format json --output security-report.json
uv run python -m core.cli --format json --output security-report.json

# Text output to file
just run --format text --output security-report.txt
uv run python -m core.cli --format text --output security-report.txt
```

### Severity Filtering
```bash
# Show only critical and high severity issues
just run --severity high
uv run python -m core.cli --severity high

# Show only critical issues
just run --severity critical
uv run python -m core.cli --severity critical
```

## Command Reference

### Main Command
```bash
devsec-audit [OPTIONS]
```

**Options:**
- `--target, -t PATH`: Target directory to scan (default: current directory)
- `--modules, -m TEXT`: Comma-separated list of modules (git,docker,vscode,secrets)
- `--format, -f [text|json|html]`: Output format (default: text)
- `--output, -o PATH`: Output file path
- `--config, -c PATH`: Configuration file path
- `--severity, -s [critical|high|medium|low|info]`: Minimum severity level
- `--quick, -q`: Quick scan - essential checks only
- `--verbose, -v`: Verbose output
- `--no-color`: Disable colored output

### Information Commands
```bash
# Show target information
just info --target /path/to/project
uv run python -m core.cli info --target /path/to/project

# List available modules
uv run python -m core.cli modules
```

## Configuration

Create a `config.yaml` file to customize scanning behavior:

```yaml
modules: ["git", "docker", "vscode", "secrets", "foundry"]
severity_filter: ["critical", "high", "medium", "low", "info"]

# Exclude paths to reduce false positives
exclude_paths:
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/openzeppelin-contracts/**"
  - "**/build/**"
  - "**/dist/**"

# Exclude specific files
exclude_files:
  - "*.test.json"
  - "*.fixture.json"

# Whitelist specific findings
whitelist:
  - id: "GIT-001"
    reason: "False positive in our environment"

# Module scoring weights
scoring:
  git: 20
  docker: 20
  vscode: 15
  secrets: 25
  foundry: 20
```

## Scoring System

DevSec Audit provides an overall security score (0-100) based on:

- **Git Security (20%)**: Configuration and repository security
- **Docker Security (20%)**: Container and image security  
- **VS Code Security (15%)**: Editor and workspace security
- **Secrets Security (25%)**: Credential and exposed file management
- **Foundry Security (20%)**: Smart contract development security

### Score Interpretation
- **85-100**: Excellent security posture ✅
- **70-84**: Good security, minor improvements needed ⚠️
- **50-69**: Moderate security, several issues to address 🟡
- **0-49**: Poor security, immediate attention required ❌

## Security Modules Detail

### Git Security Checks
- Dangerous aliases (shell command execution)
- Git hooks containing malicious scripts
- Credentials in git URLs
- SSH key permissions and encryption
- Dangerous core.editor/core.pager settings
- Git configuration analysis

### Docker Security Checks
- Unpinned base images
- Running containers as root
- Privileged containers
- Dangerous volume mounts
- Hardcoded secrets in Dockerfiles
- Exposed dangerous ports
- DevContainer security misconfigurations

### VS Code Security Checks
- Dangerous workspace settings
- Auto-execution configurations
- Suspicious terminal configurations
- Extension security validation
- Launch configuration analysis
- Workspace trust settings

### Secrets Scanner Checks
- Exposed environment files (.env, .env.*)
- Private keys and certificates (.pem, .key, id_rsa)
- Configuration files with potential secrets
- Database files not in .gitignore
- Cloud provider credential files
- .gitignore coverage validation
- Lockfile tampering detection (NPM, Yarn, etc.)

### Foundry Security Checks
- FFI (Foreign Function Interface) enabled in foundry.toml
- FFI usage in Solidity test files
- Dangerous commands in FFI calls
- Filesystem permissions configuration
- Test file security patterns

## Examples

### Comprehensive Security Audit
```bash
# Full scan with HTML report
just run --target ./my-project --format html --output audit-report.html --verbose
uv run python -m core.cli --target ./my-project --format html --output audit-report.html --verbose
```

### CI/CD Integration
```bash
# Exit with error code on critical/high issues
just run --severity high --format json --output security-findings.json
echo $?  # 0=success, 1=high issues, 2=critical issues
```

### Quick Development Check
```bash
# Fast scan for immediate feedback
just run --quick --severity high --no-color
uv run python -m core.cli --quick --severity high --no-color
```

## Integration

### GitHub Actions
```yaml
name: Security Audit
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install uv
        uses: astral-sh/setup-uv@v1
      - name: Run DevSec Audit
        run: |
          cd tools/devsec-audit
          uv run python -m core.cli --format json --output security-report.json
      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: tools/devsec-audit/security-report.json
```

### Pre-commit Hook
```bash
#!/bin/sh
# .git/hooks/pre-commit
cd tools/devsec-audit
uv run python -m core.cli --quick --severity high --no-color
exit $?
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Acknowledgments

Inspired by [Lynis](https://cisofy.com/lynis/) - the excellent security auditing tool for Unix/Linux systems.