# Suricata Rule Browser - Docker Image
# Base image: Python 3.13
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ backend/
COPY run.py .

# Create data directory for rules storage
RUN mkdir -p /app/data/rules

# Expose port 8000
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["python", "-c", "\
import uvicorn; \
import sys; \
from pathlib import Path; \
sys.path.insert(0, str(Path('/app/backend'))); \
uvicorn.run('app.main:app', host='0.0.0.0', port=8000, log_level='info')\
"]
