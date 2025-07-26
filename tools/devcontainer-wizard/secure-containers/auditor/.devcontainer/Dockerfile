FROM python:3.11-slim-bullseye

# Install only essential packages for security analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.74.0-1.3+deb11u* \
    git=1:2.30.2-1+deb11u2 \
    build-essential=12.9 \
    ca-certificates=20210119 \
    graphviz=2.42.2-5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create security auditor user
RUN groupadd -r -g 2001 auditor && \
    useradd -r -g auditor -u 2001 -m -d /home/auditor -s /bin/bash auditor

# Install Node.js for JavaScript analysis tools
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs=20.* && \
    rm -rf /var/lib/apt/lists/*

# Install Solidity compiler for analysis
RUN curl -fsSL https://github.com/ethereum/solidity/releases/download/v0.8.24/solc-static-linux -o /usr/local/bin/solc && \
    chmod +x /usr/local/bin/solc

# Install comprehensive security analysis tools
RUN pip3 install --no-cache-dir \
    slither-analyzer==0.10.0 \
    mythril==0.24.3 \
    manticore==0.3.7 \
    crytic-compile==0.3.5 \
    pyevmasm==0.2.3 \
    solc-select==1.0.4 \
    eth-abi==4.2.1 \
    eth-account==0.10.0 \
    eth-hash==0.5.2 \
    eth-keyfile==0.6.1 \
    eth-keys==0.4.0 \
    eth-rlp==0.3.0 \
    eth-typing==3.5.2 \
    eth-utils==2.3.1

# Install specialized analysis tools
RUN pip3 install --no-cache-dir \
    securify==0.1.0 \
    solidity-parser==0.1.1 \
    py-solc-x==2.0.2 \
    contract-library==0.2.0

# Install read-only Node.js analysis tools (no development dependencies)
RUN npm install -g --production \
    @ethereum/remix-analyzer@0.5.4 \
    surya@0.4.10 \
    sol2uml@2.5.18 \
    solhint@4.1.1 \
    solidity-coverage@0.8.5

# Create audit workspace and tools directory
RUN mkdir -p /audit-workspace /audit-tools /audit-reports && \
    chown -R auditor:auditor /audit-workspace /audit-tools /audit-reports /home/auditor

# Install additional forensic tools
RUN mkdir -p /opt/audit-tools && \
    curl -L https://github.com/crytic/echidna/releases/download/v2.2.1/echidna-2.2.1-Ubuntu-18.04.tar.gz | \
    tar -xz -C /opt/audit-tools && \
    chmod +x /opt/audit-tools/echidna && \
    ln -s /opt/audit-tools/echidna /usr/local/bin/echidna

# Set up audit environment
USER auditor
WORKDIR /audit-workspace

# Create audit configuration
RUN mkdir -p /home/auditor/.config/audit && \
    echo 'export PATH="/usr/local/bin:$PATH"' >> /home/auditor/.bashrc && \
    echo 'export AUDIT_MODE=true' >> /home/auditor/.bashrc && \
    echo 'export READ_ONLY_MODE=true' >> /home/auditor/.bashrc

# Create analysis aliases for convenience
RUN echo 'alias analyze="slither"' >> /home/auditor/.bashrc && \
    echo 'alias mythril-analyze="myth analyze"' >> /home/auditor/.bashrc && \
    echo 'alias graph="surya graph"' >> /home/auditor/.bashrc && \
    echo 'alias inheritance="surya inheritance"' >> /home/auditor/.bashrc && \
    echo 'alias dependencies="surya dependencies"' >> /home/auditor/.bashrc && \
    echo 'alias describe="surya describe"' >> /home/auditor/.bashrc

# Final security setup - ensure read-only mindset
RUN echo '#!/bin/bash' > /home/auditor/audit-reminder.sh && \
    echo 'echo "🔍 AUDIT MODE ACTIVE - Read-only environment"' >> /home/auditor/audit-reminder.sh && \
    echo 'echo "📊 Available tools: slither, mythril, manticore, surya, sol2uml"' >> /home/auditor/audit-reminder.sh && \
    echo 'echo "⚠️  No network access - Analysis only environment"' >> /home/auditor/audit-reminder.sh && \
    chmod +x /home/auditor/audit-reminder.sh