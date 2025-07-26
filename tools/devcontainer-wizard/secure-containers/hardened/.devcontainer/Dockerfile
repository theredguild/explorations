FROM mcr.microsoft.com/devcontainers/base:1-bullseye

# Enterprise hardening: Install minimal required packages only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.74.0-1.3+deb11u* \
    wget=1.21-1+deb11u1 \
    git=1:2.30.2-1+deb11u2 \
    build-essential=12.9 \
    python3=3.9.2-3 \
    python3-pip=20.3.4-4+deb11u1 \
    ca-certificates=20210119 \
    gnupg=2.2.27-2+deb11u2 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create enterprise-grade secure user with minimal privileges
RUN groupadd -r -g 1001 securedev && \
    useradd -r -g securedev -u 1001 -m -d /home/securedev -s /bin/bash securedev

# Install Node.js with version pinning for security
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs=20.* && \
    npm install -g npm@latest

# Install Rust with specific version for reproducible builds
USER securedev
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.75.0
ENV PATH="/home/securedev/.cargo/bin:${PATH}"
USER root

# Install Foundry in system location with version control
RUN mkdir -p /opt/foundry && \
    curl -L https://foundry.paradigm.xyz | bash && \
    FOUNDRY_DIR=/opt/foundry bash -c 'source ~/.bashrc && foundryup' && \
    chmod -R 755 /opt/foundry

# Install security analysis tools with version pinning
RUN pip3 install --no-cache-dir --user \
    slither-analyzer==0.10.0 \
    mythril==0.24.3 \
    manticore==0.3.7 \
    crytic-compile==0.3.5

# Install hardened Node.js tools
RUN npm install -g --audit-level high \
    hardhat@2.19.4 \
    @openzeppelin/contracts@5.0.1 \
    solhint@4.1.1 \
    prettier@3.1.1 \
    eslint@8.56.0

# Enterprise security: Create secure workspace structure
RUN mkdir -p /workspace && \
    mkdir -p /home/securedev/.npm && \
    mkdir -p /home/securedev/.config && \
    chown -R securedev:securedev /workspace /home/securedev

# Set up read-only system directories (will be mounted as tmpfs)
RUN mkdir -p /tmp-workspace && \
    chown securedev:securedev /tmp-workspace

# Enterprise logging and audit setup
RUN mkdir -p /var/log/devcontainer && \
    chown securedev:securedev /var/log/devcontainer

# Copy security configuration files
COPY seccomp-profile.json /etc/seccomp-profile.json
COPY hardening-setup.sh /opt/hardening-setup.sh
RUN chmod +x /opt/hardening-setup.sh

# Final security hardening
RUN chmod 755 /home/securedev && \
    chmod 700 /home/securedev/.ssh 2>/dev/null || true

# Set environment for hardened operations
ENV DEBIAN_FRONTEND=noninteractive
ENV FOUNDRY_DIR=/opt/foundry
ENV PATH="/opt/foundry/bin:${PATH}"
ENV HARDENING_ENABLED=true
ENV PYTHONPATH="/root/.local/lib/python3.9/site-packages:${PYTHONPATH}"

USER securedev
WORKDIR /workspace

# User-specific security setup
RUN echo 'export PATH="/opt/foundry/bin:$PATH"' >> /home/securedev/.bashrc && \
    echo 'alias ls="ls --color=auto"' >> /home/securedev/.bashrc && \
    echo 'alias ll="ls -alF"' >> /home/securedev/.bashrc && \
    echo 'umask 0077' >> /home/securedev/.bashrc