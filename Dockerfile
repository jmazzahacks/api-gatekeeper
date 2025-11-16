FROM python:3.13-slim

# Build argument for GitHub Personal Access Token (required for private deps)
ARG CR_PAT
ENV CR_PAT=${CR_PAT}

# Install git for private GitHub dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy CA certificate for Loki secure connection
COPY mazza.vc_CA.pem .

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash gatekeeper
RUN chown -R gatekeeper:gatekeeper /app
USER gatekeeper

# Expose the application port
EXPOSE 7843

# Set environment variables
ENV PYTHONPATH=/app
ENV PORT=7843

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:7843", "--workers", "4", "src.app:app"]
