FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
       postgresql-client \
       build-essential \
       libpq-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1. Copy requirements
COPY requirements.txt .

# 2. Install dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 3. Copy everything else (INCLUDING start.sh)
COPY . .

# 4. Make start.sh executable (AFTER copying it)
RUN chmod +x start.sh

EXPOSE 8000

# 5. Run it
CMD ["bash", "start.sh"]