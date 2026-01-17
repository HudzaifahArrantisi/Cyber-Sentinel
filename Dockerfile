# ============================================
# CyberNet Sentinel - Docker Image
# Network Security Analyzer Container
# ============================================

# Base image dengan Python 3.10
FROM python:3.10-slim-bullseye

# Metadata
LABEL maintainer="Cybersecurity Student <your-email@example.com>"
LABEL description="CyberNet Sentinel - Advanced Network Security Analyzer"
LABEL version="2.0"
LABEL org.opencontainers.image.source="https://github.com/cybersecurity-student/cybernet-sentinel"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    APP_HOME=/app \
    REPORTS_DIR=/app/reports \
    LOGS_DIR=/app/logs

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    nmap \
    tcpdump \
    net-tools \
    iputils-ping \
    iproute2 \
    dnsutils \
    # Build dependencies
    gcc \
    g++ \
    make \
    libpcap-dev \
    libpq-dev \
    # Additional utilities
    curl \
    wget \
    vim \
    git \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create app directory and user
RUN useradd -m -u 1000 -s /bin/bash sentinel && \
    mkdir -p ${APP_HOME} ${REPORTS_DIR} ${LOGS_DIR} && \
    chown -R sentinel:sentinel ${APP_HOME} ${REPORTS_DIR} ${LOGS_DIR}

# Set working directory
WORKDIR ${APP_HOME}

# Copy requirements first for better caching
COPY --chown=sentinel:sentinel requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    # Install netifaces-plus as fallback for netifaces
    pip install --no-cache-dir netifaces-plus || true

# Copy application files
COPY --chown=sentinel:sentinel . .

# Create necessary directories
RUN mkdir -p \
    ${APP_HOME}/src \
    ${APP_HOME}/tests \
    ${APP_HOME}/examples \
    ${APP_HOME}/docs \
    ${REPORTS_DIR} \
    ${LOGS_DIR}

# Set permissions
RUN chmod +x network_analyzer.py && \
    chmod -R 755 ${APP_HOME} && \
    # Allow packet capture without root
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump || true

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Display banner\n\
echo "========================================"\n\
echo "  CyberNet Sentinel Container"\n\
echo "  Network Security Analyzer"\n\
echo "========================================"\n\
echo ""\n\
echo "Container is ready!"\n\
echo ""\n\
echo "Usage:"\n\
echo "  - Interactive: docker run -it --network host --privileged cybernet-sentinel"\n\
echo "  - Background: docker run -d --network host --privileged cybernet-sentinel"\n\
echo ""\n\
echo "Available commands:"\n\
echo "  - python network_analyzer.py (main program)"\n\
echo "  - nmap (network mapper)"\n\
echo "  - tcpdump (packet analyzer)"\n\
echo ""\n\
\n\
# Execute command or start shell\n\
if [ "$#" -eq 0 ]; then\n\
    exec python network_analyzer.py\n\
else\n\
    exec "$@"\n\
fi\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

# Switch to non-root user for security
# Note: Some features require --privileged flag when running container
USER sentinel

# Expose ports (if web interface is added in future)
EXPOSE 5000 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["python", "network_analyzer.py"]

# ============================================
# Build Instructions:
# docker build -t cybernet-sentinel:latest .
# 
# Run Instructions:
# docker run -it --rm --network host --privileged cybernet-sentinel
#
# With volume mount:
# docker run -it --rm --network host --privileged \
#   -v $(pwd)/reports:/app/reports \
#   cybernet-sentinel
# ============================================
