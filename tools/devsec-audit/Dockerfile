# DevSec Audit - Docker Image
# Secure, isolated container for running security audits

FROM python:3.11-slim as builder

# Install uv for fast, secure dependency management
RUN pip install --no-cache-dir uv

# Set up working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml ./
COPY core/__init__.py ./core/

# Create virtual environment and install dependencies
RUN uv venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv pip install --no-cache-dir -e .

# Production stage
FROM python:3.11-slim

# Create non-root user for security
RUN groupadd -r devsec && useradd -r -g devsec devsec

# Install minimal system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        openssh-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Make sure we use venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY core/ ./core/
COPY modules/ ./modules/
COPY rules/ ./rules/
COPY templates/ ./templates/

# Create directory for audit reports
RUN mkdir -p /audit /reports && \
    chown -R devsec:devsec /audit /reports /app

# Switch to non-root user
USER devsec

# Default command
ENTRYPOINT ["python", "-m", "core.cli"]
CMD ["--help"]

# Labels for metadata
LABEL maintainer="DevSec Audit Team"
LABEL description="DevSecOps Security Auditor - Lynis-style tool for development environments"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/devsec-tools/devsec-audit"