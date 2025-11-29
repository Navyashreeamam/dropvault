FROM python:3.11-slim

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       postgresql-client \
       build-essential \
       libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt .

# Upgrade pip and install dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy ALL project files (including start.sh)
COPY . .

# NOW make start.sh executable (after copying it)
RUN chmod +x start.sh

# Expose port
EXPOSE 8000

# Run start script
CMD ["./start.sh"]