FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    pkg-config \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_ENV=production
ENV PORT=8000

CMD ["sh", "-c", "flask db upgrade && gunicorn --bind 0.0.0.0:$PORT app:app"]
