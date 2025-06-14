# Use Python 3.9 slim image for smaller size
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production

# Install system dependencies required for python-docx and XML processing
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user for security BEFORE copying files
RUN useradd --create-home --shell /bin/bash appuser

# Copy application code and set ownership
COPY --chown=appuser:appuser . .

# Copy and set up entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create necessary directories with proper permissions and ownership
RUN mkdir -p uploads downloads && \
    chown -R appuser:appuser /app && \
    chmod -R 755 /app && \
    chmod -R 777 uploads downloads && \
    chown -R appuser:appuser uploads downloads

USER appuser

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Expose port 1881
EXPOSE 1881

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:1881/ || exit 1

# Run the application
CMD ["python", "app.py"] 