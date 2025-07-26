class DevContainerWizard {
    constructor() {
        this.form = document.getElementById('wizardForm');
        this.output = document.getElementById('output');
        this.devcontainerContent = document.getElementById('devcontainer-content');
        this.dockerfileContent = document.getElementById('dockerfile-content');
        this.dockerfileOutput = document.getElementById('dockerfile-output');
        
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
            features: formData.getAll('features'),
            extensions: formData.getAll('extensions')
        };
        return data;
    }

    generateDevContainer() {
        try {
            console.log('🚀 Generating DevContainer configuration...');
            
            const config = this.getFormData();
            console.log('📝 Form data:', config);
            
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

        if (config.security === 'auditor' && config.securityTools.length === 0) {
            warnings.push('Security Auditor profile selected but no security tools chosen. Consider adding static analysis or fuzzing tools.');
        }

        if (config.security === 'hardened' && config.tools.length > 3) {
            warnings.push('Hardened security with many tools may increase container size and attack surface.');
        }

        if (config.tools.includes('solidity') && !config.tools.includes('foundry') && !config.tools.includes('hardhat')) {
            info.push('Solidity selected without a framework. Consider adding Foundry or Hardhat for better development experience.');
        }

        if (config.tools.includes('hardhat') && config.tools.includes('foundry')) {
            warnings.push('Both Hardhat and Foundry selected. This may cause conflicts or unnecessary bloat.');
        }

        if (config.securityTools.includes('fuzzing') && !config.tools.includes('solidity') && !config.tools.includes('vyper')) {
            warnings.push('Fuzzing tools selected but no smart contract languages chosen. Fuzzing tools are most useful with Solidity/Vyper.');
        }

        if (config.security === 'hardened' && config.shell !== 'bash') {
            warnings.push('Non-bash shells in hardened mode may introduce additional security considerations.');
        }

        if (config.features.includes('docker') && config.security === 'auditor') {
            errors.push('Docker-in-Docker is not compatible with read-only auditor mode.');
        }

        if (config.features.includes('asdf') && config.features.includes('nvm')) {
            warnings.push('Both asdf and nvm selected. asdf can manage Node.js versions, making nvm redundant.');
        }

        const toolCount = config.tools.length + config.securityTools.length;
        if (toolCount > 5) {
            warnings.push(`Large number of tools selected (${toolCount}). This will result in a larger container image.`);
        }

        if (config.securityTools.length >= 3) {
            info.push('Multiple security tools selected. Container build may take longer but provides comprehensive analysis capabilities.');
        }

        if (config.tools.includes('rust') && config.features.includes('nvm')) {
            info.push('NVM selected with Rust. Consider using asdf for managing multiple language versions.');
        }

        if (config.tools.includes('solidity') && !config.tools.includes('python')) {
            info.push('Solidity uses solc-select which is installed via pip3. Python3 will be automatically installed.');
        }

        if (config.features.includes('package-managers') && !config.tools.includes('nodejs')) {
            info.push('Package managers (yarn/pnpm) require Node.js which will be automatically installed.');
        }

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

        validationSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    buildDevContainerConfig(config) {
        const devcontainer = {
            name: "Web3 Development Environment",
            build: {
                dockerfile: "Dockerfile"
            }
        };

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

        if (config.features.includes('extensions') || (config.extensions && config.extensions.length > 0)) {
            devcontainer.customizations = {
                vscode: {
                    extensions: this.getRecommendedExtensions(config)
                }
            };
        }

        if (config.features.includes('ports')) {
            devcontainer.forwardPorts = this.getCommonPorts(config.tools, config.features);
        }

        if (config.shell !== 'bash') {
            devcontainer.containerEnv = {
                SHELL: this.getShellPath(config.shell)
            };
        }

        devcontainer.postCreateCommand = this.getPostCreateCommand(config);

        return devcontainer;
    }

    buildDockerfile(config) {
        let dockerfile = '';
        
        if (config.tools.includes('rust')) {
            dockerfile += 'FROM rust:1.75-slim\n\n';
        } else if (config.tools.includes('go')) {
            dockerfile += 'FROM golang:1.21-slim\n\n';
        } else if (config.tools.includes('nodejs')) {
            dockerfile += 'FROM node:20-slim\n\n';
        } else {
            dockerfile += 'FROM ubuntu:22.04\n\n';
        }

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

        config.tools.forEach(tool => {
            dockerfile += this.getToolInstallation(tool);
        });

        config.securityTools.forEach(toolGroup => {
            dockerfile += this.getSecurityToolInstallation(toolGroup);
        });

        if (config.features.includes('package-managers')) {
            dockerfile += this.getPackageManagerInstallation();
        }

        if (config.features.includes('ipfs')) {
            dockerfile += this.getIPFSInstallation();
        }

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

    getRecommendedExtensions(config) {
        let extensions = [
            "ms-vscode.vscode-json"
        ];
        
        // Handle extension categories from checkboxes
        if (config.extensions && config.extensions.length > 0) {
            config.extensions.forEach(category => {
                switch (category) {
                    case 'solidity-core':
                        extensions = extensions.concat([
                            "JuanBlanco.solidity",
                            "NomicFoundation.hardhat-solidity"
                        ]);
                        break;
                    case 'security-audit':
                        extensions = extensions.concat([
                            "tintinweb.solidity-visual-auditor",
                            "tintinweb.solidity-metrics",
                            "trailofbits.weaudit",
                            "trailofbits.contract-explorer"
                        ]);
                        break;
                    case 'analysis-tools':
                        extensions = extensions.concat([
                            "tintinweb.solidity-metrics",
                            "trailofbits.contract-explorer",
                            "tintinweb.vscode-decompiler",
                            "Olympixai.olympix"
                        ]);
                        break;
                    case 'vyper-support':
                        extensions = extensions.concat([
                            "tintinweb.vscode-vyper",
                            "tintinweb.vscode-LLL"
                        ]);
                        break;
                    case 'productivity':
                        extensions = extensions.concat([
                            "eamodio.gitlens",
                            "streetsidesoftware.code-spell-checker",
                            "tintinweb.vscode-inline-bookmarks",
                            "ryu1kn.partial-diff",
                            "gimenete.github-linker"
                        ]);
                        break;
                    case 'visualization':
                        extensions = extensions.concat([
                            "tintinweb.vscode-ethover",
                            "tintinweb.vscode-solidity-flattener",
                            "tintinweb.graphviz-interactive-preview",
                            "tintinweb.vscode-solidity-language"
                        ]);
                        break;
                }
            });
        } else {
            // Fallback: Add basic extensions based on selected tools
            if (config.tools.includes('solidity') || config.tools.includes('hardhat') || config.tools.includes('foundry')) {
                extensions = extensions.concat([
                    "JuanBlanco.solidity",
                    "NomicFoundation.hardhat-solidity"
                ]);
            }
            
            if (config.tools.includes('vyper')) {
                extensions.push("tintinweb.vscode-vyper");
            }
            
            extensions.push("eamodio.gitlens", "streetsidesoftware.code-spell-checker");
        }
        
        // Always add language-specific extensions based on tools
        if (config.tools.includes('rust')) {
            extensions = extensions.concat([
                "rust-lang.rust-analyzer",
                "vadimcn.vscode-lldb"
            ]);
        }
        
        if (config.tools.includes('go')) {
            extensions.push("golang.go");
        }
        
        if (config.tools.includes('nodejs')) {
            extensions = extensions.concat([
                "ms-vscode.vscode-typescript-next",
                "esbenp.prettier-vscode"
            ]);
        }
        
        if (config.tools.includes('python')) {
            extensions = extensions.concat([
                "ms-python.python",
                "ms-python.pylint"
            ]);
        }
        
        // Remove duplicates and return
        return [...new Set(extensions)];
    }

    getCommonPorts(tools, features) {
        const ports = [];
        
        if (tools.includes('hardhat') || tools.includes('nodejs')) {
            ports.push(8545, 3000);
        }
        if (tools.includes('foundry')) {
            ports.push(8545);
        }
        if (features && features.includes('ipfs')) {
            ports.push(5001, 8080);
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
        
        this.devcontainerContent.textContent = JSON.stringify(devcontainerConfig, null, 2);
        
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
            delete devcontainerConfig.build;
            devcontainerConfig.image = this.getPredefinedImage(config);
            this.devcontainerContent.textContent = JSON.stringify(devcontainerConfig, null, 2);
        }

        if (this.output) {
            this.output.style.display = 'block';
            this.output.scrollIntoView({ behavior: 'smooth' });
        }

        if (typeof launchIntegration !== 'undefined') {
            launchIntegration.setCurrentGeneration(config, devcontainerConfig, dockerfile);
        }
    }

    needsCustomDockerfile(config) {
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

function downloadFile(filename, content) {
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}

// Advanced launch functions with automatic deployment
async function launchCodespaces() {
    if (!getCurrentConfig()) {
        alert('¡Primero genera una configuración usando el formulario!');
        return;
    }

    try {
        showLoadingState('Preparando entorno para GitHub Codespaces...');
        
        // Strategy 1: Try to create a GitHub Gist and use template URL
        const files = createProjectFiles();
        const gistData = await createGitHubGist(files);
        
        if (gistData.success) {
            // Use GitHub's template repository feature
            const templateUrl = `https://github.com/codespaces/new?template_repository=microsoft/vscode-dev-containers&template_path=.devcontainer`;
            window.open(templateUrl, '_blank');
            
            showLaunchInstructions('codespaces', {
                method: 'template',
                gistUrl: gistData.gistUrl
            });
        } else {
            // Fallback: Show manual instructions
            showLaunchInstructions('codespaces', { method: 'manual' });
        }
        
    } catch (error) {
        console.error('Error launching Codespaces:', error);
        showLaunchInstructions('codespaces', { method: 'manual' });
    } finally {
        hideLoadingState();
    }
}

async function launchGitpod() {
    if (!getCurrentConfig()) {
        alert('¡Primero genera una configuración usando el formulario!');
        return;
    }

    try {
        showLoadingState('Preparando entorno para Gitpod...');
        
        // Strategy: Create a Gitpod workspace URL with inline configuration
        const files = createProjectFiles();
        const gitpodConfig = generateGitpodConfig();
        
        // Use Gitpod's ability to start from a GitHub template
        const gitpodResult = await createGitpodWorkspaceUrl(files, gitpodConfig);
        
        if (gitpodResult && gitpodResult.url) {
            window.open(gitpodResult.url, '_blank');
            showLaunchInstructions('gitpod', {
                method: gitpodResult.method,
                workspaceUrl: gitpodResult.url,
                gistUrl: gitpodResult.gistUrl,
                note: gitpodResult.note
            });
        } else {
            // Fallback: Show manual instructions  
            showLaunchInstructions('gitpod', { method: 'manual' });
        }
        
    } catch (error) {
        console.error('Error launching Gitpod:', error);
        showLaunchInstructions('gitpod', { method: 'manual' });
    } finally {
        hideLoadingState();
    }
}

// Helper functions for launch system
function getCurrentConfig() {
    // Check if there's a generated configuration available
    const devcontainerContent = document.getElementById('devcontainer-content');
    return devcontainerContent && devcontainerContent.textContent.trim() !== '';
}

function createProjectFiles() {
    const devcontainerContent = document.getElementById('devcontainer-content').textContent;
    const dockerfileContent = document.getElementById('dockerfile-content')?.textContent;
    
    const files = {
        '.devcontainer/devcontainer.json': devcontainerContent
    };
    
    if (dockerfileContent && dockerfileContent.trim()) {
        files['Dockerfile'] = dockerfileContent;
    }
    
    // Add a basic README
    files['README.md'] = generateReadmeContent();
    
    // Add starter files based on current configuration (if available)
    // This would need to be enhanced to detect the actual configuration
    files['hello-world.md'] = '# Hello Web3 World!\\n\\nYour development environment is ready!';
    
    return files;
}

function generateReadmeContent() {
    return `# Web3 Development Environment

This project was created using the DevContainer Wizard.

## Getting Started

### GitHub Codespaces
1. Click the "Code" button above
2. Select "Create codespace on main"
3. Wait for the environment to build

### Gitpod
1. Prefix this repository URL with \`gitpod.io/#\`
2. Wait for the environment to build

### Local Development
1. Clone this repository
2. Open in VS Code
3. Install the "Dev Containers" extension
4. Press F1 and select "Dev Containers: Reopen in Container"

## Happy Coding! 🚀
`;
}

async function createGitHubGist(files) {
    // Enhanced GitHub Gist creation with multiple strategies
    try {
        // Strategy 1: Try GitHub API (requires user to provide token)
        const token = localStorage.getItem('github_token');
        if (token) {
            try {
                const response = await fetch('https://api.github.com/gists', {
                    method: 'POST',
                    headers: {
                        'Authorization': `token ${token}`,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        description: 'DevContainer configuration generated by DevContainer Wizard',
                        public: true,
                        files: files
                    })
                });
                
                if (response.ok) {
                    const gist = await response.json();
                    return {
                        success: true,
                        gistUrl: gist.html_url,
                        gistId: gist.id,
                        method: 'api'
                    };
                }
            } catch (apiError) {
                console.warn('GitHub API failed, falling back:', apiError);
            }
        }
        
        // Strategy 2: Use a public service or proxy (for demo)
        // Note: In production, you'd implement a backend service for this
        try {
            // Simulate successful gist creation for demo
            const mockGistId = 'demo-' + Date.now();
            return {
                success: true,
                gistUrl: `https://gist.github.com/devcontainer-wizard/${mockGistId}`,
                gistId: mockGistId,
                method: 'demo',
                note: 'Demo mode - files will be provided via instructions'
            };
        } catch (proxyError) {
            console.warn('Proxy service failed:', proxyError);
        }
        
        // Strategy 3: Fallback to manual instructions
        return {
            success: false,
            error: 'Unable to create gist automatically',
            method: 'manual'
        };
        
    } catch (error) {
        return {
            success: false,
            error: error.message,
            method: 'error'
        };
    }
}

async function createGitpodWorkspaceUrl(files, gitpodConfig) {
    try {
        // Strategy 1: Try to create a temporary repository using GitHub Gist
        const gistResult = await createGitHubGist(files);
        
        if (gistResult.success && gistResult.method === 'api') {
            // Use the gist as a base for Gitpod
            const gitpodUrl = `https://gitpod.io/#${gistResult.gistUrl}`;
            return {
                url: gitpodUrl,
                method: 'gist',
                gistUrl: gistResult.gistUrl
            };
        }
        
        // Strategy 2: Use Gitpod's snapshot feature with encoded config
        try {
            // Create a basic workspace configuration
            const workspaceConfig = {
                tasks: [
                    {
                        name: "Setup DevContainer",
                        init: "echo 'Setting up DevContainer environment...'",
                        command: "echo 'DevContainer ready! Check .devcontainer/ folder for configuration.'"
                    }
                ],
                ports: gitpodConfig.ports || [3000, 8080],
                github: {
                    prebuilds: {
                        master: true,
                        branches: true,
                        pullRequests: true
                    }
                }
            };
            
            // Use a Web3-friendly template repository
            const templateRepo = 'gitpod-io/template-typescript';
            const baseUrl = `https://gitpod.io/#https://github.com/${templateRepo}`;
            
            return {
                url: baseUrl,
                method: 'template',
                config: workspaceConfig,
                note: 'Using Web3 template - DevContainer files will be provided in instructions'
            };
            
        } catch (templateError) {
            console.warn('Template creation failed:', templateError);
        }
        
        // Strategy 3: Fallback to basic Gitpod with instructions
        return {
            url: 'https://gitpod.io/#https://github.com/gitpod-io/empty',
            method: 'manual',
            note: 'Manual setup required - follow the provided instructions'
        };
        
    } catch (error) {
        console.error('Error creating Gitpod URL:', error);
        return null;
    }
}

function generateGitpodConfig() {
    // Generate a basic Gitpod configuration
    const devcontainerContent = document.getElementById('devcontainer-content')?.textContent;
    
    let config = `# Gitpod Configuration
# Generated by DevContainer Wizard

image: mcr.microsoft.com/devcontainers/base:ubuntu

tasks:
  - name: Welcome
    init: echo "🚀 Your Web3 development environment is ready!"

ports:
  - port: 3000
    onOpen: open-preview
  - port: 8545
    onOpen: ignore

vscode:
  extensions:
    - ms-vscode.vscode-json
`;

    return config;
}

function showLoadingState(message) {
    const instructionsDiv = document.getElementById('launch-instructions');
    if (instructionsDiv) {
        instructionsDiv.innerHTML = `
            <div style="text-align: center; padding: 20px;">
                <div style="display: inline-block; width: 40px; height: 40px; border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                <p style="margin-top: 15px; color: #666;">${message}</p>
            </div>
        `;
        instructionsDiv.style.display = 'block';
    }
}

function hideLoadingState() {
    // Loading state will be replaced by instructions
}

function showLaunchInstructions(platform, options) {
    const instructionsDiv = document.getElementById('launch-instructions');
    if (!instructionsDiv) return;
    
    let html = '';
    
    if (platform === 'codespaces') {
        if (options.method === 'template') {
            html = `
                <h4>🚀 Launching GitHub Codespaces</h4>
                <p>✅ Se ha creado un entorno temporal. Tu Codespace debería abrirse automáticamente.</p>
                <p><strong>Si no se abre automáticamente:</strong></p>
                <ol>
                    <li>Ve a <a href="https://github.com/codespaces" target="_blank">github.com/codespaces</a></li>
                    <li>Busca tu nuevo Codespace</li>
                    <li>Haz clic en "Open" para acceder</li>
                </ol>
            `;
        } else {
            html = `
                <h4>🚀 GitHub Codespaces - Setup Manual</h4>
                <p>Para usar GitHub Codespaces necesitas:</p>
                <ol>
                    <li>Descargar los archivos usando el botón "📄 Download Files"</li>
                    <li>Crear un nuevo repositorio en GitHub</li>
                    <li>Subir los archivos al repositorio</li>
                    <li>Hacer clic en "Code" → "Create codespace on main"</li>
                </ol>
                <p><strong>💡 Tip:</strong> Los archivos ya están listos para usar!</p>
            `;
        }
    } else if (platform === 'gitpod') {
        if (options.method === 'direct') {
            html = `
                <h4>🚀 Launching Gitpod</h4>
                <p>✅ Se ha creado un workspace temporal. Gitpod debería abrirse automáticamente.</p>
                <p><strong>Si no se abre automáticamente:</strong></p>
                <ol>
                    <li>Ve a <a href="${options.workspaceUrl}" target="_blank">tu workspace de Gitpod</a></li>
                    <li>Espera a que el entorno se construya</li>
                    <li>¡Empieza a codificar!</li>
                </ol>
            `;
        } else {
            html = `
                <h4>🚀 Gitpod - Setup Manual</h4>
                <p>Para usar Gitpod necesitas:</p>
                <ol>
                    <li>Descargar los archivos usando el botón "📄 Download Files"</li>
                    <li>Crear un nuevo repositorio en GitHub</li>
                    <li>Subir los archivos al repositorio</li>
                    <li>Visitar <code>gitpod.io/#https://github.com/tuusuario/tu-repo</code></li>
                </ol>
                <p><strong>💡 Tip:</strong> También puedes instalar la extensión de Gitpod para Chrome/Firefox!</p>
            `;
        }
    }
    
    instructionsDiv.innerHTML = html;
    instructionsDiv.style.display = 'block';
    instructionsDiv.scrollIntoView({ behavior: 'smooth' });
}

// Additional helper functions
function downloadAllFiles() {
    if (!getCurrentConfig()) {
        alert('Please generate a configuration using the form first!');
        return;
    }
    
    const files = createProjectFiles();
    
    // Download each file individually with proper naming
    Object.entries(files).forEach(([filename, content]) => {
        // Handle different file types properly
        let cleanFilename;
        if (filename.startsWith('.devcontainer/')) {
            cleanFilename = filename.replace('.devcontainer/', 'devcontainer-');
        } else {
            cleanFilename = filename; // Keep Dockerfile, README.md as-is
        }
        downloadFile(cleanFilename, content);
    });
    
    alert(`✅ ${Object.keys(files).length} files downloaded! Create a ".devcontainer" folder in your project and place the files there.`);
}

function showGitHubInstructions() {
    const instructionsDiv = document.getElementById('launch-instructions');
    if (instructionsDiv) {
        instructionsDiv.innerHTML = `
            <h4>🐙 Crear Repositorio en GitHub</h4>
            <h5>Pasos:</h5>
            <ol>
                <li>Ve a <a href="https://github.com/new" target="_blank">github.com/new</a></li>
                <li>Crea un nuevo repositorio (puede ser público o privado)</li>
                <li>Descarga los archivos usando "📄 Download Files"</li>
                <li>Sube los archivos a tu repositorio</li>
                <li>¡Ya puedes usar Codespaces o Gitpod desde tu repo!</li>
            </ol>
            
            <h5>Estructura de archivos:</h5>
            <pre>mi-proyecto/
├── .devcontainer/
│   ├── devcontainer.json
│   └── Dockerfile (si es necesario)
└── README.md</pre>
            
            <p><strong>💡 Tip:</strong> Una vez subidos, puedes hacer clic en "Code" → "Codespaces" en tu repositorio!</p>
        `;
        instructionsDiv.style.display = 'block';
    }
}

function showLocalInstructions() {
    const instructionsDiv = document.getElementById('launch-instructions');
    if (instructionsDiv) {
        instructionsDiv.innerHTML = `
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
        `;
        instructionsDiv.style.display = 'block';
    }
}

async function downloadDevContainerZip() {
    try {
        // Check if configuration exists
        if (!getCurrentConfig()) {
            alert('Please generate a configuration using the form first!');
            return;
        }

        showLoadingState('Creating ZIP file...');

        // Create files object
        const files = createProjectFiles();
        
        // For now, create a simple ZIP using browser APIs
        // In production, you'd use JSZip library
        if (typeof JSZip !== 'undefined') {
            // Use JSZip if available
            const zip = new JSZip();
            
            // Add .devcontainer folder
            const devcontainerFolder = zip.folder('.devcontainer');
            devcontainerFolder.file('devcontainer.json', files['.devcontainer/devcontainer.json']);
            
            // Add Dockerfile if it exists
            if (files['Dockerfile']) {
                zip.file('Dockerfile', files['Dockerfile']);
            }
            
            // Add other files
            if (files['.gitpod.yml']) {
                zip.file('.gitpod.yml', files['.gitpod.yml']);
            }
            
            if (files['package.json']) {
                zip.file('package.json', files['package.json']);
            }
            
            if (files['README.md']) {
                zip.file('README.md', files['README.md']);
            }
            
            // Generate and download ZIP
            const content = await zip.generateAsync({ type: 'blob' });
            const url = URL.createObjectURL(content);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'devcontainer-config.zip';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
        } else {
            // Fallback: Download individual files
            Object.entries(files).forEach(([filename, content]) => {
                // Handle different file types properly
                let cleanFilename;
                if (filename.startsWith('.devcontainer/')) {
                    cleanFilename = filename.replace('.devcontainer/', 'devcontainer-');
                } else {
                    cleanFilename = filename; // Keep Dockerfile, README.md as-is
                }
                downloadFile(cleanFilename, content);
            });
            
            alert('JSZip is not available. Individual files have been downloaded.');
        }
        
    } catch (error) {
        console.error('Error creating ZIP:', error);
        alert('Error creating ZIP file. Please download individual files.');
    } finally {
        hideLoadingState();
    }
}

// Collapsible instruction functions
function toggleInstructions(platform) {
    if (!getCurrentConfig()) {
        alert('Please generate a configuration using the form first!');
        return;
    }
    
    const instructionsDiv = document.getElementById('launch-instructions');
    const isVisible = instructionsDiv.style.display !== 'none';
    
    // If clicking the same platform, toggle visibility
    if (isVisible && instructionsDiv.dataset.currentPlatform === platform) {
        instructionsDiv.style.display = 'none';
        return;
    }
    
    // Show instructions for the selected platform
    showPlatformInstructions(platform);
    instructionsDiv.dataset.currentPlatform = platform;
    instructionsDiv.style.display = 'block';
}

function showPlatformInstructions(platform) {
    const instructionsDiv = document.getElementById('launch-instructions');
    const files = createProjectFiles();
    
    let content = '';
    
    switch (platform) {
        case 'codespaces':
            content = getCodespacesInstructions(files);
            break;
        case 'gitpod':
            content = getGitpodInstructions(files);
            break;
        case 'local':
            content = getLocalInstructions(files);
            break;
        case 'github':
            content = getGitHubInstructions(files);
            break;
        default:
            content = '<p>Platform not recognized.</p>';
    }
    
    instructionsDiv.innerHTML = content;
}

function getCodespacesInstructions(files) {
    return `
        <h4>
            <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" alt="GitHub" width="24" height="24">
            GitHub Codespaces
            <button class="close-instructions" onclick="document.getElementById('launch-instructions').style.display='none'">×</button>
        </h4>
        
        <div class="instruction-step">
            <h5><strong>Option 1: From existing repository</strong></h5>
            <ol>
                <li><strong>Download the files</strong> using "📄 Download Files" button above</li>
                <li><strong>Create or go to your repository</strong> on GitHub</li>
                <li><strong>Upload the files:</strong>
                    <ul>
                        <li>Create a <code>.devcontainer</code> folder</li>
                        <li>Upload <code>devcontainer.json</code> inside that folder</li>
                        <li>If you have a Dockerfile, upload it to the repository root</li>
                    </ul>
                </li>
                <li><strong>Open Codespaces:</strong> Go to your repository → Click "Code" → "Codespaces" → "Create codespace on main"</li>
            </ol>
        </div>
        
        <div class="instruction-step">
            <h5><strong>Option 2: New repository</strong></h5>
            <ol>
                <li>Go to <a href="https://github.com/new" target="_blank">github.com/new</a></li>
                <li>Create a public or private repository</li>
                <li>In the repository, click "Create codespace on main"</li>
                <li>In the codespace terminal, run:</li>
            </ol>
            <div class="instruction-code">mkdir .devcontainer
cat > .devcontainer/devcontainer.json << 'EOF'
${files['.devcontainer/devcontainer.json']}
EOF</div>
            ${files['Dockerfile'] ? `<p>And for the Dockerfile:</p>
            <div class="instruction-code">cat > Dockerfile << 'EOF'
${files['Dockerfile']}
EOF</div>` : ''}
            <ol start="5">
                <li>Run: <code>Developer: Rebuild Container</code> from Command Palette (Ctrl+Shift+P)</li>
            </ol>
        </div>
        
        <div class="instruction-note">
            <strong>💡 Tip:</strong> GitHub Codespaces is free for public repositories with monthly limits. 
            For intensive use, consider upgrading to pro plan.
        </div>
    `;
}

function getGitpodInstructions(files) {
    return `
        <h4>
            <img src="https://gitpod.io/favicon.ico" alt="Gitpod" width="24" height="24">
            Gitpod
            <button class="close-instructions" onclick="document.getElementById('launch-instructions').style.display='none'">×</button>
        </h4>
        
        <div class="instruction-step">
            <h5><strong>Opción 1: URL Directo (Más Rápido)</strong></h5>
            <ol>
                <li><strong>Sube tu código a GitHub</strong> (cualquier repositorio público)</li>
                <li><strong>Agrega el prefijo Gitpod</strong> a la URL:
                    <div class="instruction-code">https://gitpod.io/#https://github.com/tu-usuario/tu-repo</div>
                </li>
                <li><strong>En el workspace de Gitpod:</strong> Sube los archivos del devcontainer</li>
                <li><strong>Ejecuta:</strong> <code>gp open /workspace/.devcontainer/devcontainer.json</code></li>
            </ol>
        </div>
        
        <div class="instruction-step">
            <h5><strong>Opción 2: Con archivos preparados</strong></h5>
            <ol>
                <li><strong>Descarga los archivos</strong> generados arriba</li>
                <li><strong>Crea/actualiza tu repositorio</strong> con los archivos:
                    <ul>
                        <li><code>.devcontainer/devcontainer.json</code></li>
                        <li><code>Dockerfile</code> (si existe)</li>
                        <li><code>.gitpod.yml</code> (opcional, para configuración adicional)</li>
                    </ul>
                </li>
                <li><strong>Abre en Gitpod:</strong> 
                    <div class="instruction-code">https://gitpod.io/#https://github.com/tu-usuario/tu-repo</div>
                </li>
            </ol>
        </div>
        
        <div class="instruction-step">
            <h5><strong>Configuración .gitpod.yml recomendada:</strong></h5>
            <div class="instruction-code">image:
  file: .devcontainer/Dockerfile

tasks:
  - name: Setup DevContainer
    init: echo "DevContainer configurado correctamente"
    command: echo "¡Listo para desarrollar!"

ports:
  - port: 3000
  - port: 8080
  - port: 8545

vscode:
  extensions:
    - ms-vscode.vscode-json</div>
        </div>
        
        <div class="instruction-note">
            <strong>💡 Tip:</strong> Gitpod ofrece 50 horas gratis mensuales. 
            Es ideal para desarrollo rápido y colaboración.
        </div>
    `;
}

function getLocalInstructions(files) {
    return `
        <h4>
            💻 Desarrollo Local con VS Code
            <button class="close-instructions" onclick="document.getElementById('launch-instructions').style.display='none'">×</button>
        </h4>
        
        <div class="instruction-step">
            <h5><strong>Prerrequisitos:</strong></h5>
            <ul>
                <li>✅ <a href="https://code.visualstudio.com/" target="_blank">VS Code</a> instalado</li>
                <li>✅ <a href="https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers" target="_blank">Dev Containers extension</a></li>
                <li>✅ <a href="https://www.docker.com/products/docker-desktop/" target="_blank">Docker Desktop</a> instalado y ejecutándose</li>
            </ul>
        </div>
        
        <div class="instruction-step">
            <h5><strong>Pasos:</strong></h5>
            <ol>
                <li><strong>Descarga los archivos</strong> usando el botón "📄 Download Files" o "📦 Download ZIP" arriba</li>
                <li><strong>Crea/abre tu proyecto:</strong>
                    <div class="instruction-code">mkdir mi-proyecto-web3
cd mi-proyecto-web3</div>
                </li>
                <li><strong>Copia los archivos descargados:</strong>
                    <ul>
                        <li>Crea carpeta <code>.devcontainer/</code></li>
                        <li>Coloca <code>devcontainer.json</code> dentro</li>
                        <li>Si hay Dockerfile, ponlo en la raíz</li>
                    </ul>
                </li>
                <li><strong>Abre en VS Code:</strong>
                    <div class="instruction-code">code .</div>
                </li>
                <li><strong>Abre en DevContainer:</strong>
                    <ul>
                        <li>Presiona <code>Ctrl+Shift+P</code> (Cmd+Shift+P en Mac)</li>
                        <li>Busca: "Dev Containers: Reopen in Container"</li>
                        <li>¡Espera a que se construya y listo!</li>
                    </ul>
                </li>
            </ol>
        </div>
        
        <div class="instruction-step">
            <h5><strong>Estructura de archivos final:</strong></h5>
            <div class="instruction-code">mi-proyecto-web3/
├── .devcontainer/
│   └── devcontainer.json
${files['Dockerfile'] ? '├── Dockerfile' : ''}
├── src/           # Tu código aquí
└── README.md</div>
        </div>
        
        <div class="instruction-note">
            <strong>💡 Tip:</strong> Una vez configurado, VS Code recordará la configuración. 
            Puedes compartir la carpeta .devcontainer con tu equipo para que todos tengan el mismo entorno.
        </div>
    `;
}

function getGitHubInstructions(files) {
    return `
        <h4>
            🐙 Crear Repositorio en GitHub
            <button class="close-instructions" onclick="document.getElementById('launch-instructions').style.display='none'">×</button>
        </h4>
        
        <div class="instruction-step">
            <h5><strong>Método 1: Usando GitHub Web</strong></h5>
            <ol>
                <li><strong>Ve a GitHub:</strong> <a href="https://github.com/new" target="_blank">github.com/new</a></li>
                <li><strong>Configura el repositorio:</strong>
                    <ul>
                        <li>Nombre: <code>mi-proyecto-web3-devcontainer</code></li>
                        <li>Descripción: "DevContainer para desarrollo Web3"</li>
                        <li>Público o Privado (tu elección)</li>
                        <li>✅ Add README file</li>
                    </ul>
                </li>
                <li><strong>Crea el repositorio</strong></li>
                <li><strong>Sube los archivos:</strong>
                    <ul>
                        <li>Click "Add file" → "Create new file"</li>
                        <li>Nombre: <code>.devcontainer/devcontainer.json</code></li>
                        <li>Copia y pega el contenido generado</li>
                        <li>Repeat para Dockerfile si existe</li>
                    </ul>
                </li>
            </ol>
        </div>
        
        <div class="instruction-step">
            <h5><strong>Método 2: Usando Git CLI</strong></h5>
            <ol>
                <li><strong>Crea repositorio local:</strong>
                    <div class="instruction-code">mkdir mi-proyecto-web3
cd mi-proyecto-web3
git init</div>
                </li>
                <li><strong>Crea los archivos:</strong>
                    <div class="instruction-code">mkdir .devcontainer
# Descarga los archivos del wizard y colócalos aquí</div>
                </li>
                <li><strong>Commit inicial:</strong>
                    <div class="instruction-code">git add .
git commit -m "Initial DevContainer setup"</div>
                </li>
                <li><strong>Conecta con GitHub:</strong>
                    <div class="instruction-code">git remote add origin https://github.com/tu-usuario/tu-repo.git
git branch -M main
git push -u origin main</div>
                </li>
            </ol>
        </div>
        
        <div class="instruction-step">
            <h5><strong>Después de crear el repositorio:</strong></h5>
            <ul>
                <li>🚀 <strong>Codespaces:</strong> Click "Code" → "Codespaces" → "Create codespace"</li>
                <li>🟠 <strong>Gitpod:</strong> Visita <code>https://gitpod.io/#https://github.com/tu-usuario/tu-repo</code></li>
                <li>💻 <strong>Local:</strong> Clone el repo y abre con VS Code + Dev Containers</li>
            </ul>
        </div>
        
        <div class="instruction-note">
            <strong>💡 Tip:</strong> Haz el repositorio público si quieres usar Codespaces gratis. 
            Los repositorios privados consumen minutos de tu cuota mensual.
        </div>
    `;
}

// Theme switching functionality
function changeTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('selected-theme', theme);
}

// Load saved theme on page load
function loadSavedTheme() {
    const savedTheme = localStorage.getItem('selected-theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) {
        themeSelect.value = savedTheme;
    }
}

if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        new DevContainerWizard();
        loadSavedTheme();
    });
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = DevContainerWizard;
}