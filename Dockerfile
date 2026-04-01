FROM python:3.11-slim

# Security: run as non-root
RUN groupadd -r cybersentry && useradd -r -g cybersentry cybersentry

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install CyberSentry itself
RUN pip install --no-cache-dir -e .

# Create data directory
RUN mkdir -p /home/cybersentry/.cybersentry && \
    chown -R cybersentry:cybersentry /home/cybersentry /app

# Switch to non-root
USER cybersentry

# Environment
ENV CYBERSENTRY_DATABASE_URL="sqlite+aiosqlite:////home/cybersentry/.cybersentry/cybersentry.db"
ENV CYBERSENTRY_API_HOST="0.0.0.0"
ENV CYBERSENTRY_API_PORT="8765"

EXPOSE 8765

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8765/health')" || exit 1

CMD ["cybersentry", "serve", "--host", "0.0.0.0", "--port", "8765"]
