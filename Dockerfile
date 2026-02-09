FROM python:3.11-slim

WORKDIR /app

# Install ping and arp tools
RUN apt-get update && apt-get install -y \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Create volume for data persistence
VOLUME ["/app/data"]

EXPOSE 2333

CMD ["python", "app.py"]
