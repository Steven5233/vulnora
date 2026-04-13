FROM python:3.12-slim

WORKDIR /app

# Install system dependencies + scanning tools
RUN apt-get update && apt-get install -y \
    nmap \
    golang-go \
    curl \
    dirb \                  # provides the wordlist for feroxbuster
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates

# Install feroxbuster (latest release) - now real
RUN curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster-x86_64-unknown-linux-gnu.tar.gz \
    -o /tmp/ferox.tar.gz && \
    tar xzf /tmp/ferox.tar.gz -C /usr/local/bin feroxbuster && \
    chmod +x /usr/local/bin/feroxbuster && \
    rm /tmp/ferox.tar.gz

# Make sure the exact wordlist path used in scans.py exists
RUN mkdir -p /usr/share/wordlists/dirb && \
    cp /usr/share/dirb/wordlists/common.txt /usr/share/wordlists/dirb/common.txt 2>/dev/null || \
    echo -e "/admin\n/api\n/login\n/dashboard\n/backup\n/.git" > /usr/share/wordlists/dirb/common.txt

ENV PATH="/root/go/bin:${PATH}"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Create data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
