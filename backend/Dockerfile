FROM python:3.12-slim

WORKDIR /app

# Install system dependencies + scanning tools
RUN apt-get update && apt-get install -y \
    nmap \
    golang-go \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates

ENV PATH="/root/go/bin:${PATH}"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Create data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
