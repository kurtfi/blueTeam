# Rebuild AbuseIPDB analyzer with stable Python
# Original: ghcr.io/thehive-project/abuseipdb:2 (uses python:3-slim → 3.14)
# Fix: Pin to python:3.11-slim to avoid stdin/JSON parsing regression

FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim
WORKDIR /worker
COPY --from=builder /root/.local /root/.local
COPY . AbuseIPDB/
ENV PATH=/root/.local/bin:$PATH
ENTRYPOINT ["python", "AbuseIPDB/abuseipdb.py"]
