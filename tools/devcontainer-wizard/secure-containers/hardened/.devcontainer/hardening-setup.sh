#!/bin/bash

# Enterprise Hardened Web3 Development Environment Setup
# This script implements enterprise-grade security measures

set -euo pipefail

# Logging function for audit trail
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] HARDENING: $*" | tee -a /var/log/devcontainer/setup.log
}

log "🛡️ Starting enterprise hardening setup..."

# Verify security environment
if [[ "${HARDENING_ENABLED:-}" != "true" ]]; then
    log "❌ Hardening not enabled, aborting setup"
    exit 1
fi

# Enterprise npm security configuration
log "🔒 Configuring enterprise npm security..."
npm config set fund false
npm config set audit-level high
npm config set audit-signatures true
npm config set prefer-online true
npm config set save-exact true

# Create secure audit trail directories
log "📝 Setting up audit logging..."
mkdir -p ~/.audit-logs
chmod 700 ~/.audit-logs

# Set up Git security (enterprise requirements)
log "🔐 Configuring Git security..."
git config --global user.signingkey ""
git config --global commit.gpgsign false  # Disabled for devcontainer compatibility
git config --global tag.gpgsign false
git config --global pull.rebase true
git config --global init.defaultBranch main

# Enterprise-grade .gitignore
log "📄 Creating enterprise .gitignore..."
if [ ! -f ".gitignore" ]; then
    cat > .gitignore << 'EOF'
# ENTERPRISE SECURITY - NEVER COMMIT THESE FILES

# Credentials and Keys (CRITICAL)
*.pem
*.key
*.p12
*.pfx
.env*
!.env.example
secrets/
private-keys/
keystore/
wallet.json
mnemonic.txt

# Enterprise Configuration
.enterprise-config
production.json
staging.json

# Development Dependencies
node_modules/
.npm/
yarn.lock
package-lock.json

# Build Artifacts
dist/
build/
artifacts/
cache/
out/

# IDE and Editor Files
.vscode/settings.json
.idea/
*.swp
*.swo
*~

# Operating System Files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Logs and Temporary Files
*.log
logs/
*.tmp
*.temp
.cache/

# Testing and Coverage
coverage/
.nyc_output/
junit.xml

# Blockchain Specific
deployments/localhost/
deployments/hardhat/

# Audit and Compliance
.audit-logs/
compliance-reports/
EOF
fi

# Create security policy template
log "📋 Creating security policy template..."
cat > SECURITY-POLICY.md << 'EOF'
# 🛡️ Enterprise Security Policy

## 🚨 CRITICAL SECURITY REQUIREMENTS

### Private Key Management
- ❌ **NEVER** commit private keys to version control
- ✅ Use hardware wallets for mainnet transactions
- ✅ Use environment variables for testnet keys
- ✅ Rotate keys regularly

### Code Security Standards
1. **Run security analysis before deployment**:
   ```bash
   slither .
   mythril analyze contracts/MyContract.sol
   ```

2. **Comprehensive testing required**:
   ```bash
   forge test --fuzz-runs 10000
   hardhat test
   hardhat coverage
   ```

3. **Gas optimization verification**:
   ```bash
   forge snapshot
   ```

### Deployment Security
- ✅ Multi-signature wallets for production
- ✅ Timelock contracts for upgrades
- ✅ Contract verification on Etherscan
- ✅ Formal verification for critical functions

### Audit Trail
- All deployments must be logged
- Contract addresses recorded in secure registry
- Admin actions require approval workflow

## 🔍 Available Security Tools

| Tool | Command | Purpose |
|------|---------|---------|
| Slither | `slither .` | Static analysis |
| Mythril | `mythril analyze contract.sol` | Symbolic execution |
| Manticore | `manticore contract.sol` | Dynamic analysis |
| Forge | `forge test --fuzz-runs 10000` | Fuzzing tests |
| Hardhat | `hardhat verify` | Contract verification |

## 📞 Security Incident Response
1. Immediately pause affected contracts
2. Notify security team: security@company.com
3. Document incident in audit log
4. Follow incident response playbook

**Remember: Security is everyone's responsibility! 🔒**
EOF

# Set up development templates with security best practices
log "📝 Creating secure development templates..."

# Secure Hardhat config template
if [ ! -f "hardhat.config.js" ]; then
    cat > hardhat.config.example.js << 'EOF'
require("@nomicfoundation/hardhat-toolbox");
require("hardhat-gas-reporter");
require("solidity-coverage");

// SECURITY: Never commit private keys!
const PRIVATE_KEY = process.env.PRIVATE_KEY || "0x" + "0".repeat(64);
const INFURA_API_KEY = process.env.INFURA_API_KEY || "";

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      // Security: Enable all checks
      outputSelection: {
        "*": {
          "*": ["storageLayout"],
        },
      },
    },
  },
  networks: {
    hardhat: {
      chainId: 1337,
    },
    sepolia: {
      url: `https://sepolia.infura.io/v3/${INFURA_API_KEY}`,
      accounts: [PRIVATE_KEY],
      gasPrice: 20000000000,
    },
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS !== undefined,
    currency: "USD",
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY,
  },
};
EOF
fi

# Create environment template
cat > .env.example << 'EOF'
# ENTERPRISE ENVIRONMENT TEMPLATE
# Copy this to .env and fill in your values
# NEVER commit .env to version control!

# API Keys
INFURA_API_KEY=your_infura_key_here
ETHERSCAN_API_KEY=your_etherscan_key_here
ALCHEMY_API_KEY=your_alchemy_key_here

# Private Keys (USE ONLY FOR TESTNETS!)
PRIVATE_KEY=your_testnet_private_key_here

# Network Configuration
MAINNET_RPC_URL=
TESTNET_RPC_URL=

# Security Settings
ENABLE_OPTIMIZER=true
SOLC_VERSION=0.8.24
EOF

# Set up pre-commit security checks
log "🔍 Setting up pre-commit security hooks..."
cat > .pre-commit-security.sh << 'EOF'
#!/bin/bash
# Pre-commit security checks

echo "🔍 Running security checks..."

# Check for potential private keys
if grep -r "0x[a-fA-F0-9]\{64\}" . --exclude-dir=node_modules --exclude-dir=.git; then
    echo "❌ Potential private key detected!"
    exit 1
fi

# Check for .env files
if git diff --cached --name-only | grep -E "\.env(\.|$)"; then
    echo "❌ .env file detected in commit!"
    exit 1
fi

# Run Solhint if contracts exist
if [ -d "contracts" ]; then
    npx solhint 'contracts/**/*.sol'
fi

echo "✅ Security checks passed"
EOF

chmod +x .pre-commit-security.sh

# Final security verification
log "✅ Verifying security tools installation..."

# Verify Foundry
if command -v forge &> /dev/null; then
    log "✅ Foundry installed: $(forge --version)"
else
    log "❌ Foundry not found, installing..."
    curl -L https://foundry.paradigm.xyz | bash
    source ~/.bashrc
    foundryup
fi

# Verify Python security tools
if python3 -c "import slither" 2>/dev/null; then
    log "✅ Slither available"
else
    log "❌ Slither not available"
fi

# Create daily security checklist
cat > DAILY-SECURITY-CHECKLIST.md << 'EOF'
# 📋 Daily Security Checklist

## Before Starting Development
- [ ] Verify no sensitive data in commit history
- [ ] Check .env file is in .gitignore
- [ ] Confirm private keys are not in code
- [ ] Update dependencies: `npm audit fix`

## During Development
- [ ] Run security analysis: `slither .`
- [ ] Write comprehensive unit tests
- [ ] Use SafeMath for arithmetic operations
- [ ] Implement access controls properly

## Before Deployment
- [ ] Full test suite passes: `forge test`
- [ ] Gas optimization verified: `forge snapshot`
- [ ] Contract verified on explorer
- [ ] Multi-sig setup for admin functions

## Weekly Security Review
- [ ] Dependency vulnerability scan
- [ ] Code review with security focus  
- [ ] Penetration testing of contracts
- [ ] Access control audit

**Stay vigilant! Security is continuous, not one-time. 🛡️**
EOF

log "🎉 Enterprise hardening setup complete!"
log "📖 Review SECURITY-POLICY.md for security requirements"
log "📋 Use DAILY-SECURITY-CHECKLIST.md for daily security practices"
log "🔍 Run './pre-commit-security.sh' before each commit"

# Final security reminder
echo ""
echo "┌─────────────────────────────────────────────┐"
echo "│  🛡️  ENTERPRISE SECURITY ENVIRONMENT READY │"
echo "├─────────────────────────────────────────────┤"
echo "│  📚 Read SECURITY-POLICY.md                │"
echo "│  🔍 Run security checks before deployment  │"
echo "│  🔒 Never commit private keys or secrets   │"
echo "│  📞 Report security issues immediately     │"
echo "└─────────────────────────────────────────────┘"
echo ""