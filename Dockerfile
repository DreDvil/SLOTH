# ─── Builder: install Go-based tools ────────────────────────────────────────
FROM golang:1.22-bookworm AS go-builder

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ─── Runtime image ───────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# System security tools available in Debian/Kali repos
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        nikto \
        sslscan \
        whatweb \
        dirsearch \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Go-built binaries from builder stage
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/nuclei    /usr/local/bin/nuclei

WORKDIR /app

# Install Python deps first (layer cache-friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY start.py    ./
COPY templates/  ./templates/

# Persist scan output and config outside the container
VOLUME ["/app/scans", "/app/config.yaml"]

# API server port
EXPOSE 8000

ENTRYPOINT ["python", "start.py"]
# Default: interactive TUI. Override with subcommand:
#   docker run sloth scan example.com --json
#   docker run -p 8000:8000 sloth serve
CMD []
