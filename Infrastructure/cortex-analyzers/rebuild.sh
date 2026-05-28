#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# rebuild_cortex_analyzers.sh
#
# Cortex analizör imajlarını Python 3.11 ile yeniden build eder.
# Sebep: GHCR'deki resmi imajlar "python:3-slim/alpine" kullanıyor ve bu
#        tag şu an Python 3.14'e çözümleniyor. Python 3.14'te cortexutils
#        kütüphanesinin stdin JSON okuma mekanizması çalışmıyor.
#
# Kullanım:
#   cd Infrastructure
#   bash cortex-analyzers/rebuild.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() {
  docker rm abuse-extract-tmp 2>/dev/null || true
  docker rm vt-extract-tmp 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. AbuseIPDB ─────────────────────────────────────────────────────────────
echo "━━━ [1/2] AbuseIPDB analyzer ━━━"
ABUSE_TMP=$(mktemp -d)
echo "  → Extracting worker files from original image..."
docker rm abuse-extract-tmp 2>/dev/null || true
docker create --name abuse-extract-tmp ghcr.io/thehive-project/abuseipdb:2
docker cp abuse-extract-tmp:/worker/AbuseIPDB/. "$ABUSE_TMP/"
docker rm abuse-extract-tmp

# Dockerfile'ı kendi yazdığımızla değiştir
cp "$SCRIPT_DIR/abuseipdb/Dockerfile" "$ABUSE_TMP/Dockerfile"

echo "  → Building with Python 3.11-slim..."
docker build -t ghcr.io/thehive-project/abuseipdb:2 "$ABUSE_TMP"
echo "  ✓ ghcr.io/thehive-project/abuseipdb:2 rebuilt"
rm -rf "$ABUSE_TMP"

# ── 2. VirusTotal ────────────────────────────────────────────────────────────
echo ""
echo "━━━ [2/2] VirusTotal analyzer ━━━"
VT_TMP=$(mktemp -d)
echo "  → Extracting worker files from original image..."
docker rm vt-extract-tmp 2>/dev/null || true
docker create --name vt-extract-tmp ghcr.io/thehive-project/virustotal_getreport:3
docker cp vt-extract-tmp:/worker/VirusTotal/. "$VT_TMP/"
docker rm vt-extract-tmp

# Dockerfile'ı kendi yazdığımızla değiştir
cp "$SCRIPT_DIR/virustotal/Dockerfile" "$VT_TMP/Dockerfile"

echo "  → Building with Python 3.11-alpine..."
docker build -t ghcr.io/thehive-project/virustotal_getreport:3 "$VT_TMP"
echo "  ✓ ghcr.io/thehive-project/virustotal_getreport:3 rebuilt"
rm -rf "$VT_TMP"

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "━━━ Verification ━━━"
echo -n "  AbuseIPDB Python: "
docker run --rm --entrypoint python ghcr.io/thehive-project/abuseipdb:2 --version
echo -n "  VirusTotal Python: "
docker run --rm --entrypoint python ghcr.io/thehive-project/virustotal_getreport:3 --version
echo ""
echo "✓ All analyzer images rebuilt. Cortex will use the new images for future jobs."
