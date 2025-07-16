FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    pkg-config \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Environment variables
ENV FLASK_ENV=production
ENV PORT=8000

# Run migrations and start Gunicorn
CMD ["sh", "-c", "flask db upgrade && gunicorn --bind 0.0.0.0:$PORT app:app"]
```
