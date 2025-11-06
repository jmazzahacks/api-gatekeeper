FROM python:3.13-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose the application port
EXPOSE 7843

# Set environment variables
ENV PYTHONPATH=/app
ENV PORT=7843

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:7843", "--workers", "4", "src.app:app"]
