class DevContainerWizard {
    constructor() {
        this.form = document.getElementById('wizardForm');
        this.output = document.getElementById('output');
        this.devcontainerContent = document.getElementById('devcontainer-content');
        this.dockerfileContent = document.getElementById('dockerfile-content');
        this.dockerfileOutput = document.getElementById('dockerfile-output');
        
        // Verify required elements exist
        if (!this.form) {
            console.error('❌ Could not find form element with id "wizardForm"');
            return;
        }
        if (!this.output) {
            console.error('❌ Could not find output element with id "output"');
            return;
        }
        
        this.init();
    }

    init() {
        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.generateDevContainer();
        });
        console.log('✅ DevContainer Wizard initialized successfully');
    }

    getFormData() {
        const formData = new FormData(this.form);
        const data = {
            security: formData.get('security'),
            shell: formData.get('shell'),
            tools: formData.getAll('tools'),
            securityTools: formData.getAll('security-tools'),
            features: formData.getAll('features')
        };
        return data;
    }

    generateDevContainer() {
        try {
            console.log('🚀 Generating DevContainer configuration...');
            
            const config = this.getFormData();
            console.log('📝 Form data:', config);
            
            // Validate configuration
            const validationResults = this.validateConfiguration(config);
            this.displayValidationResults(validationResults);
            
            const devcontainerConfig = this.buildDevContainerConfig(config);
            const dockerfile = this.buildDockerfile(config);
            
            this.displayOutput(devcontainerConfig, dockerfile, config);
            
            console.log('✅ DevContainer generation completed successfully');
        } catch (error) {
            console.error('❌ Error generating DevContainer:', error);
            alert('An error occurred while generating the DevContainer. Please check the console for details.');
        }
    }

    validateConfiguration(config) {
        const warnings = [];
        const errors = [];
        const info = [];

        // Security profile validation
        if (config.security === 'auditor' && config.securityTools.length === 0) {
            warnings.push('Security Auditor profile selected but no security tools chosen. Consider adding static analysis or fuzzing tools.');
        }

        if (config.security === 'hardened' && config.tools.length > 3) {
            warnings.push('Hardened security with many tools may increase container size and attack surface.');
        }

        // Tool combination validation
        if (config.tools.includes('solidity') && !config.tools.includes('foundry') && !config.tools.includes('hardhat')) {
            info.push('Solidity selected without a framework. Consider adding Foundry or Hardhat for better development experience.');
        }

        if (config.tools.includes('hardhat') && config.tools.includes('foundry')) {
            warnings.push('Both Hardhat and Foundry selected. This may cause conflicts or unnecessary bloat.');
        }

        if (config.securityTools.includes('fuzzing') && !config.tools.includes('solidity') && !config.tools.includes('vyper')) {
            warnings.push('Fuzzing tools selected but no smart contract languages chosen. Fuzzing tools are most useful with Solidity/Vyper.');
        }

        // Shell and security validation
        if (config.security === 'hardened' && config.shell !== 'bash') {
            warnings.push('Non-bash shells in hardened mode may introduce additional security considerations.');
        }

        // Feature validation
        if (config.features.includes('docker') && config.security === 'auditor') {
            errors.push('Docker-in-Docker is not compatible with read-only auditor mode.');
        }

        if (config.features.includes('asdf') && config.features.includes('nvm')) {
            warnings.push('Both asdf and nvm selected. asdf can manage Node.js versions, making nvm redundant.');
        }

        // Resource usage warnings
        const toolCount = config.tools.length + config.securityTools.length;
        if (toolCount > 5) {
            warnings.push(`Large number of tools selected (${toolCount}). This will result in a larger container image.`);
        }

        if (config.securityTools.length >= 3) {
            info.push('Multiple security tools selected. Container build may take longer but provides comprehensive analysis capabilities.');
        }

        // Compatibility checks
        if (config.tools.includes('rust') && config.features.includes('nvm')) {
            info.push('NVM selected with Rust. Consider using asdf for managing multiple language versions.');
        }

        // Tool dependency validation
        if (config.tools.includes('solidity') && !config.tools.includes('python')) {
            info.push('Solidity uses solc-select which is installed via pip3. Python3 will be automatically installed.');
        }

        // Package manager validation
        if (config.features.includes('package-managers') && !config.tools.includes('nodejs')) {
            info.push('Package managers (yarn/pnpm) require Node.js which will be automatically installed.');
        }

        // IPFS validation
        if (config.features.includes('ipfs') && !config.features.includes('ports')) {
            warnings.push('IPFS selected but ports not forwarded. Consider enabling port forwarding for IPFS API (5001) and Gateway (8080).');
        }

        return {
            errors,
            warnings,
            info,
            hasIssues: errors.length > 0 || warnings.length > 0
        };
    }

    displayValidationResults(results) {
        const validationSection = document.getElementById('validation-results');
        const messagesDiv = document.getElementById('validation-messages');

        if (!validationSection || !messagesDiv) {
            console.warn('⚠️ Validation result elements not found, skipping validation display');
            return;
        }

        if (!results.hasIssues && results.info.length === 0) {
            validationSection.style.display = 'none';
            return;
        }

        let html = '';

        results.errors.forEach(error => {
            html += `<div class="validation-message validation-error">❌ ${error}</div>`;
        });

        results.warnings.forEach(warning => {
            html += `<div class="validation-message validation-warning">⚠️ ${warning}</div>`;
        });

        results.info.forEach(info => {
            html += `<div class="validation-message validation-info">💡 ${info}</div>`;
        });

        messagesDiv.innerHTML = html;
        validationSection.style.display = 'block';

        // Scroll to validation results
        validationSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    buildDevContainerConfig(config) {
        const devcontainer = {
            name: "Web3 Development Environment",
            build: {
                dockerfile: "Dockerfile"
            }
        };

        // Security configurations
        if (config.security === 'auditor') {
            devcontainer.mounts = [
                "source=${localWorkspaceFolder},target=/workspace,type=bind,readonly"
            ];
            devcontainer.containerUser = "nobody";
            devcontainer.runArgs = [
                "--security-opt=no-new-privileges",
                "--cap-drop=ALL",
                "--read-only"
            ];
        } else if (config.security === 'hardened') {
            devcontainer.runArgs = [
                "--security-opt=no-new-privileges",
                "--security-opt=seccomp=/etc/docker/seccomp-profiles/default-no-chmod.json",
                "--security-opt=apparmor:docker-default",
                "--cap-drop=ALL",
                "--cap-add=DAC_OVERRIDE",
                "--read-only"
            ];
            devcontainer.mounts = [
                "source=${localWorkspaceFolder},target=/workspace,type=bind",
                "target=/tmp,type=tmpfs",
                "target=/var/tmp,type=tmpfs"
            ];
        } else if (config.security === 'secure') {
            devcontainer.runArgs = [
                "--security-opt=no-new-privileges",
                "--cap-drop=ALL",
                "--cap-add=DAC_OVERRIDE",
                "--cap-add=SETGID",
                "--cap-add=SETUID"
            ];
        }

        // Features
        devcontainer.features = {};
        
        if (config.features.includes('git')) {
            devcontainer.features["ghcr.io/devcontainers/features/git:1"] = {};
        }
        
        if (config.features.includes('docker')) {
            devcontainer.features["ghcr.io/devcontainers/features/docker-in-docker:2"] = {};
        }

        if (config.features.includes('asdf')) {
            devcontainer.features["ghcr.io/devcontainers-contrib/features/asdf-package:1"] = {};
        }

        if (config.features.includes('nvm')) {
            devcontainer.features["ghcr.io/devcontainers/features/node:1"] = {};
        }

        // Extensions
        if (config.features.includes('extensions')) {
            devcontainer.customizations = {
                vscode: {
                    extensions: this.getRecommendedExtensions(config.tools, config.securityTools)
                }
            };
        }

        // Port forwarding
        if (config.features.includes('ports')) {
            devcontainer.forwardPorts = this.getCommonPorts(config.tools, config.features);
        }

        // Shell configuration
        if (config.shell !== 'bash') {
            devcontainer.containerEnv = {
                SHELL: this.getShellPath(config.shell)
            };
        }

        // Post-create command for shell setup
        devcontainer.postCreateCommand = this.getPostCreateCommand(config);

        return devcontainer;
    }

    buildDockerfile(config) {
        let dockerfile = '';
        
        // Base image selection based on primary stack
        if (config.tools.includes('rust')) {
            dockerfile += 'FROM rust:1.75-slim\n\n';
        } else if (config.tools.includes('go')) {
            dockerfile += 'FROM golang:1.21-slim\n\n';
        } else if (config.tools.includes('nodejs')) {
            dockerfile += 'FROM node:20-slim\n\n';
        } else {
            dockerfile += 'FROM ubuntu:22.04\n\n';
        }

        // Security hardening for hardened profiles
        if (config.security === 'hardened' || config.security === 'auditor') {
            dockerfile += `# Security hardening
RUN groupadd -r devuser && useradd -r -g devuser devuser
RUN apt-get update && apt-get install -y --no-install-recommends \\
    ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

# Install security profiles
RUN mkdir -p /etc/docker/seccomp-profiles
COPY seccomp-profile.json /etc/docker/seccomp-profiles/default-no-chmod.json

`;
        }

        // Install basic tools and dependencies
        dockerfile += `# Install basic tools and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    curl \\
    wget \\
    unzip \\
    python3 \\
    python3-pip \\
    python3-venv \\
    ${config.features.includes('git') ? 'git \\' : ''}
    && rm -rf /var/lib/apt/lists/*

`;

        // Shell installation
        if (config.shell === 'zsh') {
            dockerfile += `# Install Zsh and Oh My Zsh
RUN apt-get update && apt-get install -y zsh \\
    && rm -rf /var/lib/apt/lists/* \\
    && sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

`;
        } else if (config.shell === 'fish') {
            dockerfile += `# Install Fish shell
RUN apt-get update && apt-get install -y fish \\
    && rm -rf /var/lib/apt/lists/*

`;
        }

        // Tool-specific installations
        config.tools.forEach(tool => {
            dockerfile += this.getToolInstallation(tool);
        });

        // Security tools installation
        config.securityTools.forEach(toolGroup => {
            dockerfile += this.getSecurityToolInstallation(toolGroup);
        });

        // Package managers
        if (config.features.includes('package-managers')) {
            dockerfile += this.getPackageManagerInstallation();
        }

        // IPFS installation
        if (config.features.includes('ipfs')) {
            dockerfile += this.getIPFSInstallation();
        }

        // Security configurations
        if (config.security === 'auditor') {
            dockerfile += `# Set up read-only user for security auditing
USER devuser
WORKDIR /workspace
`;
        } else if (config.security === 'hardened') {
            dockerfile += `# Set up secure user with minimal privileges
USER devuser
WORKDIR /workspace
`;
        } else {
            dockerfile += `# Set working directory
WORKDIR /workspace
`;
        }

        return dockerfile;
    }

    getToolInstallation(tool) {
        const installations = {
            solidity: `# Install Solidity compiler and solc-select
RUN pip3 install solc-select && \\
    solc-select install 0.8.21 && \\
    solc-select use 0.8.21

`,
            vyper: `# Install Vyper
RUN pip3 install vyper

`,
            hardhat: `# Install Hardhat (requires Node.js)
RUN if ! command -v node &> /dev/null; then \\
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \\
        apt-get install -y nodejs; \\
    fi \\
    && npm install -g hardhat

`,
            foundry: `# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash \\
    && /root/.foundry/bin/foundryup

ENV PATH="/root/.foundry/bin:$PATH"

`,
            nodejs: `# Node.js already installed or will be installed
RUN if ! command -v node &> /dev/null; then \\
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \\
        apt-get install -y nodejs; \\
    fi

`,
            python: `# Install Python Web3 libraries
RUN pip3 install web3 eth-brownie

`,
            rust: `# Rust already installed or will be installed
RUN if ! command -v rustc &> /dev/null; then \\
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \\
        . $HOME/.cargo/env; \\
    fi

`,
            go: `# Go already installed or will be installed
RUN if ! command -v go &> /dev/null; then \\
        wget https://golang.org/dl/go1.21.5.linux-amd64.tar.gz && \\
        tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \\
        rm go1.21.5.linux-amd64.tar.gz; \\
    fi

ENV PATH="/usr/local/go/bin:$PATH"

`
        };

        return installations[tool] || '';
    }

    getSecurityToolInstallation(toolGroup) {
        const installations = {
            'fuzzing': `# Install Fuzzing Tools
RUN # Install Medusa
    wget https://github.com/crytic/medusa/releases/latest/download/medusa-linux-x64.tar.gz && \\
    tar -xzf medusa-linux-x64.tar.gz && \\
    mv medusa /usr/local/bin/ && \\
    rm medusa-linux-x64.tar.gz && \\
    # Install Echidna
    wget https://github.com/crytic/echidna/releases/latest/download/echidna-test-2.2.1-Ubuntu-18.04.tar.gz && \\
    tar -xzf echidna-test-2.2.1-Ubuntu-18.04.tar.gz && \\
    mv echidna-test /usr/local/bin/echidna && \\
    rm echidna-test-2.2.1-Ubuntu-18.04.tar.gz

`,
            'static-analysis': `# Install Static Analysis Tools
RUN pip3 install slither-analyzer slitherin semgrep aderyn && \\
    # Install Slither LSP
    pip3 install slither-lsp

`,
            'symbolic-execution': `# Install Symbolic Execution Tools
RUN pip3 install mythril && \\
    # Install Halmos
    pip3 install halmos

`,
            'decompilers': `# Install Decompiler Tools
RUN pip3 install panoramix-decompiler && \\
    # Install Heimdall
    wget https://github.com/Jon-Becker/heimdall-rs/releases/latest/download/heimdall-linux && \\
    chmod +x heimdall-linux && \\
    mv heimdall-linux /usr/local/bin/heimdall

`,
            'forensics': `# Install Forensics Tools
RUN pip3 install napalm-blockchain && \\
    apt-get update && apt-get install -y --no-install-recommends \\
    hexdump \\
    xxd \\
    binutils \\
    && rm -rf /var/lib/apt/lists/*

`
        };

        return installations[toolGroup] || '';
    }

    getPackageManagerInstallation() {
        return `# Install Additional Package Managers
RUN # Install Node.js if not already installed (needed for yarn/pnpm)
    if ! command -v node &> /dev/null; then \\
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \\
        apt-get install -y nodejs && \\
        rm -rf /var/lib/apt/lists/*; \\
    fi && \\
    # Install yarn and pnpm
    npm install -g yarn pnpm && \\
    # Install pipx
    python3 -m pip install pipx && \\
    # Install uv (fast Python package installer)
    curl -LsSf https://astral.sh/uv/install.sh | sh

`;
    }

    getIPFSInstallation() {
        return `# Install IPFS
RUN apt-get update && apt-get install -y wget && \\
    rm -rf /var/lib/apt/lists/* && \\
    wget https://dist.ipfs.tech/kubo/v0.24.0/kubo_v0.24.0_linux-amd64.tar.gz && \\
    tar -xzf kubo_v0.24.0_linux-amd64.tar.gz && \\
    cd kubo && ./install.sh && \\
    cd .. && rm -rf kubo* && \\
    ipfs --version

`;
    }

    getRecommendedExtensions(tools, securityTools) {
        const extensions = [
            "ms-vscode.vscode-json",
            "streetsidesoftware.code-spell-checker",
            "eamodio.gitlens"
        ];

        // Core development tools
        if (tools.includes('solidity')) {
            extensions.push(
                "JuanBlanco.solidity", 
                "tintinweb.solidity-visual-auditor",
                "NomicFoundation.hardhat-solidity"
            );
        }
        if (tools.includes('vyper')) {
            extensions.push("tintinweb.vyper");
        }
        if (tools.includes('rust')) {
            extensions.push("rust-lang.rust-analyzer");
        }
        if (tools.includes('go')) {
            extensions.push("golang.go");
        }
        if (tools.includes('nodejs')) {
            extensions.push("ms-vscode.vscode-typescript-next", "esbenp.prettier-vscode");
        }
        if (tools.includes('python')) {
            extensions.push("ms-python.python", "ms-python.pylint");
        }

        // Security tools extensions
        if (securityTools && securityTools.includes('static-analysis')) {
            extensions.push("trailofbits.slither-vscode");
        }

        return extensions;
    }

    getCommonPorts(tools, features) {
        const ports = [];
        
        if (tools.includes('hardhat') || tools.includes('nodejs')) {
            ports.push(8545, 3000); // Hardhat node, React dev server
        }
        if (tools.includes('foundry')) {
            ports.push(8545); // Anvil node
        }
        if (features && features.includes('ipfs')) {
            ports.push(5001, 8080); // IPFS API, Gateway
        }

        return ports.length > 0 ? ports : [8545, 3000];
    }

    getShellPath(shell) {
        const shells = {
            bash: '/bin/bash',
            zsh: '/bin/zsh',
            fish: '/usr/bin/fish'
        };
        return shells[shell] || '/bin/bash';
    }

    getPostCreateCommand(config) {
        const commands = [];
        
        if (config.shell === 'zsh') {
            commands.push('chsh -s /bin/zsh');
        } else if (config.shell === 'fish') {
            commands.push('chsh -s /usr/bin/fish');
        }

        if (config.tools.includes('nodejs')) {
            commands.push('npm install -g yarn pnpm');
        }

        return commands.length > 0 ? commands.join(' && ') : undefined;
    }

    displayOutput(devcontainerConfig, dockerfile, config) {
        if (!this.devcontainerContent) {
            console.error('❌ devcontainer-content element not found');
            return;
        }
        
        // Show devcontainer.json
        this.devcontainerContent.textContent = JSON.stringify(devcontainerConfig, null, 2);
        
        // Show Dockerfile if needed
        const needsDockerfile = this.needsCustomDockerfile(config);
        if (needsDockerfile) {
            if (this.dockerfileContent) {
                this.dockerfileContent.textContent = dockerfile;
            }
            if (this.dockerfileOutput) {
                this.dockerfileOutput.style.display = 'block';
            }
        } else {
            if (this.dockerfileOutput) {
                this.dockerfileOutput.style.display = 'none';
            }
            // Use predefined image instead
            delete devcontainerConfig.build;
            devcontainerConfig.image = this.getPredefinedImage(config);
            this.devcontainerContent.textContent = JSON.stringify(devcontainerConfig, null, 2);
        }

        if (this.output) {
            this.output.style.display = 'block';
            this.output.scrollIntoView({ behavior: 'smooth' });
        }

        // Set current generation for launch integration
        if (typeof launchIntegration !== 'undefined') {
            launchIntegration.setCurrentGeneration(config, devcontainerConfig, dockerfile);
        }
    }

    needsCustomDockerfile(config) {
        // Custom Dockerfile needed for security hardening, security tools, multiple tools, or specific shells
        return config.security === 'hardened' || 
               config.security === 'auditor' ||
               config.securityTools.length > 0 ||
               config.tools.length > 1 ||
               config.shell !== 'bash' ||
               config.tools.includes('foundry') ||
               config.tools.includes('solidity') ||
               config.tools.includes('vyper') ||
               config.features.includes('package-managers') ||
               config.features.includes('ipfs');
    }

    getPredefinedImage(config) {
        if (config.tools.includes('nodejs')) {
            return 'mcr.microsoft.com/devcontainers/javascript-node:20';
        } else if (config.tools.includes('python')) {
            return 'mcr.microsoft.com/devcontainers/python:3.11';
        } else if (config.tools.includes('rust')) {
            return 'mcr.microsoft.com/devcontainers/rust:1';
        } else if (config.tools.includes('go')) {
            return 'mcr.microsoft.com/devcontainers/go:1.21';
        }
        return 'mcr.microsoft.com/devcontainers/base:ubuntu';
    }
}

// Download functionality
function downloadFile(filename, content) {
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}

// Launch integrations
class LaunchIntegration {
    constructor() {
        this.currentConfig = null;
        this.currentDevcontainer = null;
        this.currentDockerfile = null;
    }

    setCurrentGeneration(config, devcontainer, dockerfile) {
        this.currentConfig = config;
        this.currentDevcontainer = devcontainer;
        this.currentDockerfile = dockerfile;
    }

    createProjectFiles() {
        const files = {};
        
        // Always include devcontainer.json
        files['.devcontainer/devcontainer.json'] = JSON.stringify(this.currentDevcontainer, null, 2);
        
        // Include Dockerfile if needed
        if (this.currentDockerfile) {
            files['.devcontainer/Dockerfile'] = this.currentDockerfile;
        }
        
        // Create a basic README
        files['README.md'] = this.generateReadme();
        
        // Create sample files based on selected tools
        if (this.currentConfig.tools.includes('solidity')) {
            files['contracts/HelloWorld.sol'] = this.getSolidityTemplate();
        }
        if (this.currentConfig.tools.includes('nodejs')) {
            files['package.json'] = this.getPackageJsonTemplate();
            files['src/index.js'] = this.getNodeJsTemplate();
        }
        if (this.currentConfig.tools.includes('python')) {
            files['main.py'] = this.getPythonTemplate();
            files['requirements.txt'] = this.getPythonRequirements();
        }
        if (this.currentConfig.tools.includes('rust')) {
            files['Cargo.toml'] = this.getRustCargoTemplate();
            files['src/main.rs'] = this.getRustTemplate();
        }
        
        return files;
    }

    generateReadme() {
        const tools = this.currentConfig.tools.join(', ') || 'none';
        const securityTools = this.currentConfig.securityTools.join(', ') || 'none';
        
        return `# Web3 Development Environment

This project was created using the DevContainer Wizard for Web3 development.

## Configuration
- **Security Profile**: ${this.currentConfig.security}
- **Shell**: ${this.currentConfig.shell}
- **Development Tools**: ${tools}
- **Security Tools**: ${securityTools}

## Getting Started

### Option 1: GitHub Codespaces
1. Click the "Code" button on this repository
2. Select "Create codespace on main"
3. Wait for the environment to build

### Option 2: Local Development
1. Clone this repository
2. Open in VS Code
3. Install the "Dev Containers" extension
4. Press F1 and select "Dev Containers: Reopen in Container"

### Option 3: Gitpod
1. Click the Gitpod button or prefix the repository URL with \`gitpod.io/#\`
2. Wait for the environment to build

## Tools Included
${this.currentConfig.tools.map(tool => `- ${tool.charAt(0).toUpperCase() + tool.slice(1)}`).join('\n')}

${this.currentConfig.securityTools.length > 0 ? `## Security Tools
${this.currentConfig.securityTools.map(tool => `- ${tool.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}`).join('\n')}` : ''}

## Happy Coding! 🚀
`;
    }

    getSolidityTemplate() {
        return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract HelloWorld {
    string public message;
    
    constructor(string memory _message) {
        message = _message;
    }
    
    function setMessage(string memory _message) public {
        message = _message;
    }
    
    function getMessage() public view returns (string memory) {
        return message;
    }
}
`;
    }

    getPackageJsonTemplate() {
        return JSON.stringify({
            "name": "web3-devcontainer-project",
            "version": "1.0.0",
            "description": "Web3 project created with DevContainer Wizard",
            "main": "src/index.js",
            "scripts": {
                "start": "node src/index.js",
                "test": "echo \\\"Error: no test specified\\\" && exit 1"
            },
            "dependencies": {
                "ethers": "^6.0.0"
            },
            "devDependencies": {},
            "keywords": ["web3", "ethereum", "blockchain"],
            "author": "",
            "license": "MIT"
        }, null, 2);
    }

    getNodeJsTemplate() {
        return `const { ethers } = require('ethers');

console.log('🚀 Web3 Development Environment Ready!');
console.log('Ethers.js version:', ethers.version);

// Example: Connect to a provider
// const provider = new ethers.JsonRpcProvider('https://mainnet.infura.io/v3/YOUR-PROJECT-ID');

async function main() {
    console.log('Hello from your Web3 development environment!');
    
    // Add your Web3 code here
}

main().catch(console.error);
`;
    }

    getPythonTemplate() {
        return `#!/usr/bin/env python3
"""
Web3 Development Environment
Created with DevContainer Wizard
"""

from web3 import Web3

def main():
    print("🚀 Web3 Development Environment Ready!")
    print(f"Web3.py version: {Web3.__version__}")
    
    # Example: Connect to a provider
    # w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR-PROJECT-ID'))
    # print(f"Connected: {w3.is_connected()}")
    
    print("Hello from your Web3 development environment!")

if __name__ == "__main__":
    main()
`;
    }

    getPythonRequirements() {
        return `web3>=6.0.0
eth-brownie
requests
`;
    }

    getRustCargoTemplate() {
        return `[package]
name = "web3-devcontainer-project"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
`;
    }

    getRustTemplate() {
        return `use std::println;

#[tokio::main]
async fn main() {
    println!("🚀 Web3 Development Environment Ready!");
    println!("Hello from your Rust Web3 development environment!");
    
    // Add your Web3 Rust code here
}
`;
    }
}

const launchIntegration = new LaunchIntegration();

// GitHub Codespaces integration
async function launchCodespaces() {
    if (!launchIntegration.currentDevcontainer) {
        alert('Please generate a devcontainer configuration first!');
        return;
    }

    try {
        // Create a GitHub repository with the devcontainer files
        const files = launchIntegration.createProjectFiles();
        const repoData = await createGitHubGist(files);
        
        if (repoData.gistUrl) {
            // Open GitHub with the gist - user can then create a repository from it
            const instructionsDiv = document.getElementById('launch-instructions');
            instructionsDiv.innerHTML = \`
                <h4>🚀 Launch in GitHub Codespaces</h4>
                <ol>
                    <li>Your devcontainer files have been prepared</li>
                    <li><a href="\${repoData.gistUrl}" target="_blank">Click here to view your configuration gist</a></li>
                    <li>Create a new repository on GitHub and add these files</li>
                    <li>Click "Code" → "Create codespace on main" in your repository</li>
                    <li>Your devcontainer will build automatically with all selected tools!</li>
                </ol>
                <p><strong>Tip:</strong> You can also download the ZIP file and upload it to a new GitHub repository.</p>
            \`;
            instructionsDiv.style.display = 'block';
        }
    } catch (error) {
        console.error('Error creating GitHub integration:', error);
        showFallbackInstructions('codespaces');
    }
}

// Gitpod integration  
async function launchGitpod() {
    if (!launchIntegration.currentDevcontainer) {
        alert('Please generate a devcontainer configuration first!');
        return;
    }

    try {
        const files = launchIntegration.createProjectFiles();
        
        // Create .gitpod.yml configuration
        files['.gitpod.yml'] = generateGitpodConfig();
        
        const repoData = await createGitHubGist(files);
        
        if (repoData.gistUrl) {
            const instructionsDiv = document.getElementById('launch-instructions');
            instructionsDiv.innerHTML = \`
                <h4>🚀 Launch in Gitpod</h4>
                <ol>
                    <li>Your devcontainer and Gitpod files have been prepared</li>
                    <li><a href="\${repoData.gistUrl}" target="_blank">Click here to view your configuration gist</a></li>
                    <li>Create a new repository on GitHub and add these files</li>
                    <li>Prefix your repository URL with <code>gitpod.io/#</code></li>
                    <li>Example: <code>gitpod.io/#https://github.com/yourusername/your-repo</code></li>
                    <li>Your environment will build automatically with all selected tools!</li>
                </ol>
                <p><strong>Alternative:</strong> Install the Gitpod browser extension for one-click launches.</p>
            \`;
            instructionsDiv.style.display = 'block';
        }
    } catch (error) {
        console.error('Error creating Gitpod integration:', error);
        showFallbackInstructions('gitpod');
    }
}

function generateGitpodConfig() {
    const tasks = [];
    
    if (launchIntegration.currentConfig.tools.includes('nodejs')) {
        tasks.push({
            name: "Install Dependencies",
            init: "npm install"
        });
    }
    
    if (launchIntegration.currentConfig.tools.includes('python')) {
        tasks.push({
            name: "Setup Python",
            init: "pip install -r requirements.txt"
        });
    }

    const config = {
        image: {
            file: ".devcontainer/Dockerfile"
        },
        tasks,
        ports: launchIntegration.currentDevcontainer.forwardPorts || [],
        vscode: {
            extensions: launchIntegration.currentDevcontainer.customizations?.vscode?.extensions || []
        }
    };

    // Generate YAML manually since we don't have js-yaml
    let yaml = \`# Gitpod Configuration
# Generated by DevContainer Wizard

\`;

    // Add image configuration
    if (launchIntegration.currentDockerfile) {
        yaml += \`image:
  file: .devcontainer/Dockerfile

\`;
    } else {
        yaml += \`image: \${launchIntegration.currentDevcontainer.image || 'mcr.microsoft.com/devcontainers/base:ubuntu'}

\`;
    }

    // Add tasks
    if (tasks.length > 0) {
        yaml += \`tasks:
\`;
        tasks.forEach((task, index) => {
            yaml += \`  - name: \${task.name}
    init: \${task.init}
\`;
        });
        yaml += '\\n';
    }

    // Add ports
    const ports = launchIntegration.currentDevcontainer.forwardPorts;
    if (ports && ports.length > 0) {
        yaml += \`ports:
\${ports.map(port => \`  - port: \${port}\`).join('\\n')}

\`;
    }

    // Add VS Code extensions
    const extensions = launchIntegration.currentDevcontainer.customizations?.vscode?.extensions;
    if (extensions && extensions.length > 0) {
        yaml += \`vscode:
  extensions:
\${extensions.map(ext => \`    - \${ext}\`).join('\\n')}
\`;
    }

    return yaml;
}

// Local launch instructions
function showLocalInstructions() {
    if (!launchIntegration.currentDevcontainer) {
        alert('Please generate a devcontainer configuration first!');
        return;
    }

    const instructionsDiv = document.getElementById('launch-instructions');
    instructionsDiv.innerHTML = \`
        <h4>💻 Launch Locally</h4>
        <h5>Prerequisites:</h5>
        <ul>
            <li>Docker Desktop installed and running</li>
            <li>VS Code with "Dev Containers" extension</li>
        </ul>
        
        <h5>Steps:</h5>
        <ol>
            <li>Download your devcontainer files using the buttons above</li>
            <li>Create a new project folder</li>
            <li>Create a <code>.devcontainer</code> folder inside your project</li>
            <li>Place the downloaded files in the <code>.devcontainer</code> folder</li>
            <li>Open the project folder in VS Code</li>
            <li>Press <kbd>F1</kbd> and select "Dev Containers: Reopen in Container"</li>
            <li>Wait for the container to build (first time may take several minutes)</li>
        </ol>
        
        <h5>Alternative - Command Line:</h5>
        <pre>mkdir my-web3-project
cd my-web3-project
# Place your devcontainer files here
code .
# Then use VS Code's "Reopen in Container" command</pre>
        
        <p><strong>Tip:</strong> Use the "Download Project ZIP" button for a complete starter project!</p>
    \`;
    instructionsDiv.style.display = 'block';
}

// Download complete project ZIP
function downloadDevContainerZip() {
    if (!launchIntegration.currentDevcontainer) {
        alert('Please generate a devcontainer configuration first!');
        return;
    }

    try {
        const files = launchIntegration.createProjectFiles();
        createAndDownloadZip(files, 'web3-devcontainer-project.zip');
    } catch (error) {
        console.error('Error creating ZIP:', error);
        alert('Error creating ZIP file. Please try downloading files individually.');
    }
}

// Helper function to create GitHub Gist
async function createGitHubGist(files) {
    // Since we can't directly create gists without authentication,
    // we'll provide the user with the files and instructions
    return {
        gistUrl: null,
        files: files
    };
}

// Fallback instructions when API calls fail
function showFallbackInstructions(platform) {
    const instructionsDiv = document.getElementById('launch-instructions');
    const platformName = platform === 'codespaces' ? 'GitHub Codespaces' : 'Gitpod';
    
    instructionsDiv.innerHTML = \`
        <h4>🚀 Launch in \${platformName}</h4>
        <p><strong>Manual Setup Required:</strong></p>
        <ol>
            <li>Download your devcontainer files using the buttons above</li>
            <li>Create a new repository on GitHub</li>
            <li>Upload the devcontainer files to your repository</li>
            <li>
                \${platform === 'codespaces' 
                    ? 'Click "Code" → "Create codespace on main"'
                    : 'Visit <code>gitpod.io/#https://github.com/yourusername/your-repo</code>'
                }
            </li>
            <li>Your environment will build automatically!</li>
        </ol>
    \`;
    instructionsDiv.style.display = 'block';
}

// Create and download ZIP file
function createAndDownloadZip(files, filename) {
    // Simple ZIP creation without external libraries
    // This creates a downloadable folder structure
    let zipContent = '';
    
    for (const [filePath, content] of Object.entries(files)) {
        // For simplicity, we'll create individual downloads
        // In a real implementation, you'd use a ZIP library like JSZip
        const fileName = filePath.replace('/', '-');
        downloadFile(fileName, content);
    }
    
    // Show success message
    alert(\`Project files downloaded! \${Object.keys(files).length} files created. Create a folder structure as shown in the local instructions.\`);
}

// Initialize the wizard when the page loads (browser only)
if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        new DevContainerWizard();
    });
}

// Export for Node.js environment
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DevContainerWizard;
}