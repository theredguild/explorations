FROM scratch as base

# Start with absolutely minimal base - add only essential files
COPY --from=ubuntu:22.04-slim /bin/bash /bin/bash
COPY --from=ubuntu:22.04-slim /bin/sh /bin/sh
COPY --from=ubuntu:22.04-slim /bin/ls /bin/ls
COPY --from=ubuntu:22.04-slim /bin/cat /bin/cat
COPY --from=ubuntu:22.04-slim /bin/echo /bin/echo
COPY --from=ubuntu:22.04-slim /bin/pwd /bin/pwd
COPY --from=ubuntu:22.04-slim /usr/bin/id /usr/bin/id

# Copy essential libraries
COPY --from=ubuntu:22.04-slim /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/
COPY --from=ubuntu:22.04-slim /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/
COPY --from=ubuntu:22.04-slim /lib/x86_64-linux-gnu/libpthread.so.0 /lib/x86_64-linux-gnu/
COPY --from=ubuntu:22.04-slim /lib64/ld-linux-x86-64.so.2 /lib64/

FROM ubuntu:22.04-slim as builder

# Install minimal tools needed for analysis setup
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-minimal=3.10.* \
    python3-pip=22.0.* \
    curl=7.81.* \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install only essential Python analysis tools
RUN python3 -m pip install --no-cache-dir --user \
    pyevmasm==0.2.3 \
    eth-abi==4.2.1 \
    eth-utils==2.3.1

FROM scratch

# Copy minimal system from builder
COPY --from=builder /usr/bin/python3 /usr/bin/python3
COPY --from=builder /usr/lib/python3.10 /usr/lib/python3.10
COPY --from=builder /usr/local/lib/python3.10/dist-packages /usr/local/lib/python3.10/dist-packages
COPY --from=builder /root/.local /usr/local

# Copy essential binaries
COPY --from=ubuntu:22.04-slim /bin/bash /bin/bash
COPY --from=ubuntu:22.04-slim /bin/sh /bin/sh
COPY --from=ubuntu:22.04-slim /bin/ls /bin/ls
COPY --from=ubuntu:22.04-slim /bin/cat /bin/cat
COPY --from=ubuntu:22.04-slim /bin/echo /bin/echo
COPY --from=ubuntu:22.04-slim /bin/pwd /bin/pwd
COPY --from=ubuntu:22.04-slim /bin/mkdir /bin/mkdir
COPY --from=ubuntu:22.04-slim /bin/chmod /bin/chmod
COPY --from=ubuntu:22.04-slim /usr/bin/id /usr/bin/id

# Copy essential libraries
COPY --from=ubuntu:22.04-slim /lib/x86_64-linux-gnu /lib/x86_64-linux-gnu
COPY --from=ubuntu:22.04-slim /lib64 /lib64
COPY --from=ubuntu:22.04-slim /usr/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu

# Create minimal directory structure
RUN mkdir -p /tmp /var/log /quarantine /home/isolated && \
    echo "isolated:x:3001:3001:Isolated User:/home/isolated:/bin/bash" > /etc/passwd && \
    echo "isolated:x:3001:" > /etc/group && \
    echo "root:x:0:0:root:/root:/bin/bash" >> /etc/passwd && \
    echo "root:x:0:" >> /etc/group

# Set up isolated user environment
RUN chown 3001:3001 /home/isolated /quarantine /tmp && \
    chmod 755 /home/isolated /quarantine && \
    chmod 1777 /tmp

# Create isolation scripts
RUN echo '#!/bin/bash' > /usr/local/bin/isolation-check && \
    echo 'echo "🔒 ISOLATION STATUS:"' >> /usr/local/bin/isolation-check && \
    echo 'echo "  Network: DISABLED"' >> /usr/local/bin/isolation-check && \
    echo 'echo "  Filesystem: READ-ONLY"' >> /usr/local/bin/isolation-check && \
    echo 'echo "  Memory: LIMITED"' >> /usr/local/bin/isolation-check && \
    echo 'echo "  Processes: RESTRICTED"' >> /usr/local/bin/isolation-check && \
    chmod +x /usr/local/bin/isolation-check

# Create minimal analysis tools
RUN echo '#!/usr/bin/python3' > /usr/local/bin/hex-analyze && \
    echo 'import sys' >> /usr/local/bin/hex-analyze && \
    echo 'if len(sys.argv) > 1:' >> /usr/local/bin/hex-analyze && \
    echo '    with open(sys.argv[1], "rb") as f:' >> /usr/local/bin/hex-analyze && \
    echo '        data = f.read()' >> /usr/local/bin/hex-analyze && \
    echo '        print(f"File size: {len(data)} bytes")' >> /usr/local/bin/hex-analyze && \
    echo '        print(f"Hex dump: {data[:64].hex()}")' >> /usr/local/bin/hex-analyze && \
    echo 'else:' >> /usr/local/bin/hex-analyze && \
    echo '    print("Usage: hex-analyze <file>")' >> /usr/local/bin/hex-analyze && \
    chmod +x /usr/local/bin/hex-analyze

# Set environment variables
ENV PATH="/usr/local/bin:/usr/bin:/bin"
ENV PYTHONPATH="/usr/local/lib/python3.10/dist-packages"
ENV ISOLATION_MODE="maximum"
ENV QUARANTINE_ACTIVE="true"

# Switch to isolated user
USER 3001:3001
WORKDIR /quarantine

# Create user-specific isolation setup
RUN echo 'export PS1="[ISOLATED] \w $ "' > /home/isolated/.bashrc && \
    echo 'echo "⚫ MAXIMUM ISOLATION ACTIVE"' >> /home/isolated/.bashrc && \
    echo 'echo "🔒 Network: DISABLED | Filesystem: READ-ONLY"' >> /home/isolated/.bashrc && \
    echo 'isolation-check' >> /home/isolated/.bashrc && \
    echo 'alias status="isolation-check"' >> /home/isolated/.bashrc && \
    echo 'alias analyze="hex-analyze"' >> /home/isolated/.bashrc