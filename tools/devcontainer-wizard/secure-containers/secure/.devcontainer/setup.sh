#!/bin/bash

# Secure Web3 Development Environment Setup
# This script runs after container creation to finalize the secure setup

set -e

echo "🛡️ Setting up secure Web3 development environment..."

# Ensure foundry is accessible
if ! command -v forge &> /dev/null; then
    echo "Installing Foundry for current user..."
    curl -L https://foundry.paradigm.xyz | bash
    source ~/.bashrc
    foundryup
fi

# Set up secure npm configuration
echo "🔒 Configuring secure npm settings..."
npm config set fund false
npm config set audit-level high

# Initialize a basic hardhat project if none exists
if [ ! -f "hardhat.config.js" ] && [ ! -f "hardhat.config.ts" ]; then
    echo "📦 Initializing Hardhat project..."
    npx hardhat init --yes || true
fi

# Set up basic security linting
echo "🔍 Setting up security linting..."
if [ ! -f ".solhint.json" ]; then
    cat > .solhint.json << 'EOF'
{
  "extends": "solhint:recommended",
  "rules": {
    "func-visibility": ["error", { "ignoreConstructors": true }],
    "state-visibility": "error",
    "no-unused-vars": "error",
    "const-name-snakecase": "error",
    "contract-name-camelcase": "error",
    "event-name-camelcase": "error",
    "function-name-mixedcase": "error",
    "modifier-name-mixedcase": "error",
    "var-name-mixedcase": "error",
    "imports-on-top": "error",
    "ordering": "error",
    "visibility-modifier-order": "error"
  }
}
EOF
fi

# Create basic .gitignore for security
if [ ! -f ".gitignore" ]; then
    echo "🔐 Creating secure .gitignore..."
    cat > .gitignore << 'EOF'
# Dependencies
node_modules/

# Production builds
dist/
build/
artifacts/
cache/

# Environment variables (NEVER commit these!)
.env
.env.local
.env.production
.env.staging

# Private keys (NEVER commit these!)
*.pem
*.key
private-keys/
secrets/

# IDE files
.vscode/settings.json
.idea/

# OS files
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Temporary files
*.tmp
*.temp
EOF
fi

# Set up basic security reminders
echo "📝 Creating security reminders..."
cat > SECURITY.md << 'EOF'
# 🛡️ Security Guidelines

## ⚠️ CRITICAL: Never commit private keys!

- Use environment variables for sensitive data
- Keep `.env` files in `.gitignore`
- Use hardware wallets for mainnet interactions
- Run `slither .` before deploying contracts
- Use `hardhat verify` for contract verification

## 🔍 Security Tools Available:

- **Slither**: `slither .` - Static analysis
- **Mythril**: `myth analyze contract.sol` - Symbolic execution
- **Solhint**: `solhint 'contracts/**/*.sol'` - Linting
- **Hardhat**: Built-in testing and deployment tools

## 🧪 Testing Best Practices:

1. Write comprehensive unit tests
2. Use fuzzing with Foundry: `forge test --fuzz-runs 1000`
3. Test edge cases and overflow conditions
4. Mock external calls and oracles
5. Test access control and permissions

Stay secure! 🔒
EOF

echo "✅ Secure Web3 development environment setup complete!"
echo "🔍 Run 'slither .' to analyze your contracts for vulnerabilities"
echo "🧪 Run 'forge test' to run your test suite"
echo "📖 Check SECURITY.md for security guidelines"