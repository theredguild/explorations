# Security Research Explorations 🔍

A collection of experimental security tools and proof-of-concepts developed during security research. These tools are designed for educational purposes and defensive security analysis.

**⚠️ Important**: All tools in this repository are experimental and may be unstable. They are shared for research and educational purposes. Use at your own risk.

## Tools

### 🛡️ DevSec Audit
**Path**: `tools/devsec-audit/`

A comprehensive security scanner for development environments, inspired by Lynis. Scans projects for security misconfigurations across Git, Docker, VS Code, exposed secrets, and smart contract development (Foundry).

- Multi-module security scanning (Git, Docker, VS Code, Secrets, Foundry)
- Configurable exclusions to reduce false positives  
- Multiple output formats (text, JSON, HTML)
- CI/CD integration support
- Lockfile tampering detection

**Quick Start**:
```bash
cd tools/devsec-audit
just run --target /path/to/project
```

### 🔌 VSCode Extension Inspector  
**Path**: `tools/vscode-extension-inspector/`

A Python tool for monitoring and analyzing VSCode marketplace extensions. Helps identify potentially malicious extensions through metadata analysis, download patterns, and publisher verification.

- Search extensions by keywords, tags, and dates
- Suspicious pattern detection (unverified publishers, low downloads, etc.)
- Download extensions for deeper analysis
- Continuous monitoring with Discord alerts
- Publisher verification checks

**Quick Start**:
```bash
cd tools/vscode-extension-inspector
python VSExInspector.py --keywords "solidity,ethereum" --analyze
```

### 🎯 Test Repositories
**Paths**: `tools/backdoored-test-repo/`, `tools/backdoored-test-repo-2/`

Intentionally vulnerable test repositories containing various security issues for testing security tools and demonstrating attack vectors. These repositories contain examples of:

- Git configuration vulnerabilities
- Exposed secrets and credentials
- Docker security misconfigurations
- VS Code malicious tasks and settings
- Supply chain attack vectors (lockfile tampering, typosquatting)
- Smart contract security issues (FFI usage, dangerous configurations)

**Note**: These are intentionally insecure repositories for testing purposes only.

## Getting Started

Each tool has its own README with detailed installation and usage instructions. Most tools are designed to run independently with minimal setup.

### General Requirements
- Python 3.7+
- Git
- Basic command-line familiarity

### Installation Patterns
Most tools follow these patterns:
- **uv** (recommended): `uv run python script.py`
- **Just**: `just run` (where available)
- **Direct**: `python script.py`
- **Docker**: Available for some tools

## Contributing

This repository contains experimental research tools. While contributions are welcome, please note:

1. Tools may have incomplete features or documentation
2. Breaking changes can occur without notice
3. Focus is on security research rather than production stability
4. Each tool maintains its own coding standards

## Disclaimer

These tools are provided for educational and research purposes only. Users are responsible for:

- Complying with applicable laws and regulations
- Using tools ethically and responsibly  
- Understanding the risks of experimental software
- Properly securing any sensitive data encountered

## License

See the [LICENSE](LICENSE) file for details.