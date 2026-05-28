# Rebuild VirusTotal analyzer with stable Python
# Original: ghcr.io/thehive-project/virustotal_getreport:3 (uses python:3-alpine → 3.14)
# Fix: Pin to python:3.11-alpine to avoid stdin/JSON parsing regression

FROM python:3.11-alpine

WORKDIR /worker

# install runtime dependencies
RUN apk add --no-cache perl-image-exiftool file-dev

COPY requirements.txt VirusTotal/

# Install Python dependencies from requirements.txt
RUN pip install --no-cache-dir -r VirusTotal/requirements.txt

COPY . VirusTotal

ENTRYPOINT ["python", "VirusTotal/virustotal.py"]
