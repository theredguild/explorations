# Security Policy

## Overview

DevSec Audit is a security auditing tool designed to help identify vulnerabilities in development environments. As a security tool itself, we take the security of this project seriously.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in DevSec Audit, please report it responsibly:

### 🔒 **Private Disclosure**
1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Send details to: security@devsec-audit.org (or create a private security advisory)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### 🕒 **Response Timeline**
- **24 hours**: Initial acknowledgment
- **7 days**: Preliminary assessment
- **30 days**: Fix and disclosure (if applicable)

## Security Considerations for Users

### 🛡️ **Running DevSec Audit Safely**

DevSec Audit analyzes your code and configuration files. To run it safely:

#### ✅ **Recommended: Isolated Environments**
```bash
# Use Docker (completely isolated)
docker run --rm -v /path/to/project:/audit devsec-audit --target /audit

# Use uv (isolated Python environment)
just setup && just scan

# Use dedicated VM or container
```

#### ⚠️ **What DevSec Audit Does**
- **Reads files** in the target directory
- **Analyzes configuration** files (git, docker, vscode)
- **Scans for patterns** in source code
- **Does NOT execute** any code from your project
- **Does NOT make network** requests (except for updates)
- **Does NOT modify** your files

#### 🚫 **What DevSec Audit Does NOT Do**
- Execute arbitrary code from scanned projects
- Send data to external services
- Modify your source code or configurations
- Install additional software without permission

### 🔍 **Trusting the Scanner**

#### **Source Code Verification**
All source code is available for inspection:
- Core scanner: `core/scanner.py`
- Security modules: `modules/`
- Rules definitions: `rules/`

#### **Dependency Security**
We use minimal, well-vetted dependencies:
- `click` - CLI framework
- `pyyaml` - YAML parsing
- `jinja2` - Report templating
- `gitpython` - Git analysis
- `colorama` - Terminal colors

#### **Isolation Mechanisms**
1. **Docker**: Complete container isolation
2. **uv**: Virtual environment isolation  
3. **No sudo**: Never requires elevated privileges
4. **Read-only**: Only reads files, never executes

### 🏗️ **Development Security**

#### **For Contributors**
- All dependencies managed through `uv` for security
- Pre-commit hooks include security scanners
- Code review required for all changes
- No secrets in repository (use `detect-secrets`)

#### **Build Security**
```bash
# Verify dependencies
just audit-deps

# Run security linting
just quality

# Check for secrets
pre-commit run detect-secrets --all-files
```

## Known Security Considerations

### 🔸 **File System Access**
DevSec Audit requires read access to scan directories. It:
- Only reads text-based configuration and source files
- Skips binary files and large files
- Respects `.gitignore` patterns for efficiency
- Never writes to scanned directories

### 🔸 **Memory Usage**
Large codebases may consume significant memory:
- Use `--quick` flag for faster, lighter scans
- Consider Docker limits for very large projects
- Monitor system resources during scans

### 🔸 **False Positives**
Security scanners can have false positives:
- Review findings before taking action
- Use configuration files to whitelist known safe patterns
- Understand the context of your specific environment

## Security Best Practices for Users

### 🎯 **Before Running**
1. **Review the tool**: Understand what it does
2. **Use isolation**: Prefer Docker or uv over system pip
3. **Backup important data**: Though not modified, be safe
4. **Test on non-critical projects** first

### 🎯 **During Scanning**
1. **Monitor resource usage**: Large scans can be intensive
2. **Review output carefully**: Not all findings are critical
3. **Don't trust blindly**: Understand each recommendation

### 🎯 **After Scanning**
1. **Validate findings**: Confirm issues are real
2. **Prioritize by severity**: Fix critical issues first
3. **Test changes**: Ensure fixes don't break functionality
4. **Re-scan**: Verify issues are resolved

## Supply Chain Security

### 📦 **Dependencies**
- All dependencies are pinned to specific versions
- Regular security audits of dependencies
- Minimal dependency footprint
- No runtime downloads of additional components

### 🔐 **Distribution**
- Source code available on GitHub
- Reproducible builds through `uv` and `just`
- Container images built from scratch
- No binary distributions (compile from source)

## Contact

For security concerns or questions:
- 🔒 Security issues: security@devsec-audit.org
- 💬 General questions: issues@devsec-audit.org
- 📚 Documentation: See README.md

## Acknowledgments

We appreciate security researchers and users who help improve DevSec Audit's security posture through responsible disclosure.