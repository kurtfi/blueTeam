# Security Model & Hardening Guide

Agentix / BlueTeam platformunun güvenlik mimarisi, tehdit modeli ve sertleştirme kılavuzu.

> **Scope:** Bu doküman platform düzeyindeki güvenliği kapsar. Wazuh/Elasticsearch gibi
> bileşenlerin kendi güvenlik yapılandırmaları için ilgili ürün belgelerine bakılmalıdır.

---

## Güvenlik Katmanları Özeti

```
┌─────────────────────────────────────────────────────────────┐
│                    HARICI İSTEKLER                          │
│              (Browser / API Client / Wazuh)                 │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS / JWT
┌──────────────────────────▼──────────────────────────────────┐
│                 API GATEWAY (Port 8001)                      │
│   • JWT doğrulama        • Rate limiting                     │
│   • CORS denetimi        • Origin whitelisting               │
│   • Request logging      • Header sanitization              │
└──────────────────────────┬──────────────────────────────────┘
                           │ X-Internal-Api-Key (Internal)
┌──────────────────────────▼──────────────────────────────────┐
│                  CORE API (Port 8000)                        │
│   • Tool sandbox         • Workspace izolasyonu             │
│   • Disk quota           • Path traversal koruması          │
│   • HITL approval        • Structlog audit trail            │
└────────────┬─────────────────────────┬───────────────────────┘
             │ FastMCP Protocol        │ Redis / Postgres
┌────────────▼────────────┐  ┌────────▼────────────────────────┐
│  TRIAGE CORE (Port 8081)│  │  DATA LAYER                      │
│  Playbook yürütme        │  │  • Redis: session state          │
│  SOC araç adaptörleri    │  │  • Postgres: agent config        │
└─────────────────────────┘  └──────────────────────────────────┘
```

---

## 1. Kimlik Doğrulama ve Yetkilendirme

### 1.1 Çift Katmanlı Auth Modeli

| Katman | Mekanizma | Uygulama Noktası |
|---|---|---|
| **Harici (Browser → Gateway)** | JWT Bearer Token | `X-Authorization: Bearer <token>` |
| **Dahili (Gateway → Core)** | Pre-shared key | `X-Internal-Api-Key: <key>` |
| **WebHook (Wazuh → Gateway)** | Path-based secret token | `/webhook/wazuh/{token}` |

### 1.2 JWT Doğrulama (Gateway Katmanı)

Gateway, her istekte JWT'yi doğrular. Token içeriğinden `user_id` ve `roles` çekilir ve Core'a `X-User-Id` / `X-User-Roles` header'ları ile iletilir.

**Kritik Yapılandırma:**

```env
# .env
AGENTIX_JWT_SECRET=<en az 32 karakter güçlü rastgele dize>
AGENTIX_JWT_ALGORITHM=HS256       # veya RS256
AGENTIX_JWT_EXPIRE_MINUTES=60
```

> [!WARNING]
> Varsayılan `dev-internal-key-change-me-in-production` değeri **asla** production'da kullanılmamalıdır. `AGENTIX_INTERNAL_API_KEY`'i `openssl rand -hex 32` ile üret.

### 1.3 Dahili API Key (Gateway → Core)

Core API, Gateway'den gelen tüm isteklerde `X-Internal-Api-Key` header'ını kontrol eder.
Bu header eşleşmezse istek `403 Forbidden` ile reddedilir.

```python
# src/Agentix/agentix/api/server.py'deki kontrol
if request.headers.get("X-Internal-Api-Key") != settings.agentix_internal_api_key:
    raise HTTPException(status_code=403, detail="Forbidden")
```

### 1.4 WebHook Token Doğrulama

Wazuh'dan gelen webhook'lar bir path parametresi olarak gizli token içerir:

```
POST /webhook/wazuh/{WAZUH_WEBHOOK_SECRET_TOKEN}
```

Bu token `.env`'de tanımlanır ve Gateway tarafından doğrulanır.

---

## 2. Network Güvenliği

### 2.1 CORS Politikası

Gateway, sadece `GATEWAY_ALLOWED_ORIGINS` içinde listelenen origin'lere izin verir:

```env
GATEWAY_ALLOWED_ORIGINS=https://app.yourdomain.com,https://soc.yourdomain.com
```

**Production'da** `*` (wildcard) kullanmak güvensizdir — asla yapılmamalıdır.

### 2.2 Servis İzolasyonu (Docker)

Tüm servislerin Docker Compose ağı üzerinde **iç ağda** konuşlandırılması gerekir. Sadece Gateway dış dünyaya açık olmalıdır:

```yaml
# docker-compose.yml (önerilen yapı)
services:
  gateway:
    ports:
      - "8001:8001"    # Dışa açık tek port
  core:
    # Port expose edilmez — sadece internal network
    expose:
      - "8000"
  triage:
    expose:
      - "8081"
  redis:
    # Dışa kesinlikle açılmamalı
    expose:
      - "6379"
  postgres:
    expose:
      - "5432"
```

### 2.3 TLS / HTTPS

Production ortamında Gateway önüne bir reverse proxy (nginx / Traefik) konulmalı ve TLS sonlandırması burada yapılmalıdır:

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/ssl/certs/agentix.crt;
    ssl_certificate_key /etc/ssl/private/agentix.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://gateway:8001;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 3. Dosya Sistemi Güvenliği (SessionWorkspace)

### 3.1 Path Traversal Koruması

Her araç çağrısında dosya yolu `SessionWorkspace.resolve_path()` üzerinden geçirilir.
Yol session root'unun dışına çıkıyorsa `PermissionError` fırlatılır:

```python
def resolve_path(self, relative_path: str, subdirectory: str = "outputs") -> Path:
    base = self.root / subdirectory
    resolved = (base / relative_path).resolve()

    # Kritik güvenlik kontrolü:
    if not str(resolved).startswith(str(self.root.resolve())):
        raise PermissionError(
            f"Access denied: '{relative_path}' is outside the workspace boundary."
        )
    return resolved
```

**Kapsanan Saldırı Vektörü:**

```
../../../etc/passwd          → PermissionError ✓
../../.env                   → PermissionError ✓
outputs/../../../etc/shadow  → PermissionError ✓
```

### 3.2 Disk Quota Zorlama

Her session için maksimum disk kullanımı sınırlanır. Yazma öncesinde `check_quota()` çağrılır:

```env
AGENTIX_SESSION_QUOTA_MB=100    # Varsayılan: 100 MB per session
```

Aşıldığında:
```python
raise PermissionError("Session workspace quota exceeded: X / Y bytes.")
```

### 3.3 Session Sahipliği Doğrulama

Workspace erişimi `owner_id` ile kısıtlanır. Farklı kullanıcının session'ına erişim `False` döner:

```python
def validate_access(self, owner_id: str) -> bool:
    if self.owner_id == "anonymous":
        return True  # Development modu
    return self.owner_id == owner_id
```

> [!IMPORTANT]
> Production'da `owner_id = "anonymous"` olmamasına dikkat et. Bu durum tüm kullanıcılara çapraz erişim verir.

### 3.4 Workspace Dizin Yapısı

```
workspace/sessions/{session_id}/
├── downloads/     # Araçların indirdiği geçici dosyalar (cleanup'ta silinir)
├── outputs/       # Kalıcı raporlar (cleanup'ta KORUNUR)
├── uploads/       # Kullanıcı yüklemeleri (cleanup'ta KORUNUR)
├── temp/          # Geçici işlem dosyaları (cleanup'ta silinir)
└── .session_meta.json  # Session metadata (owner_id, quota, status)
```

---

## 4. Human-in-the-Loop (HITL) Güvenliği

### 4.1 Onay Gerektiren Araçlar

Geri döndürülemez veya yüksek riskli araç çağrıları (`requires_confirmation=True`) kullanıcı onayı olmadan yürütülmez:

```python
# Orchestrator'daki kontrol (core/orchestrator.py)
if tool.requires_confirmation(**t_args) and not t_args.get("approved"):
    # Durumu kaydet, onay iste
    await self._memory.set_metadata(session_id, "draft_history", messages)
    yield ReActStep(StepType.CONFIRM, ...)
    return  # Yürütme durur
```

### 4.2 Onay Akışı

```
Kullanıcı İsteği
     │
     ▼
Orchestrator: tool.requires_confirmation() == True?
     │ Evet
     ▼
draft_history Redis'e kaydedilir
CONFIRM adımı yield edilir (Teams/Slack bildirim gönderilir)
     │
     ▼
Kullanıcı "yes" / "evet" / "confirm" yazar
     │
     ▼
draft_history yüklenir, araç force_approved=True ile çalışır
```

**Güvenli Onay Kelimeleri:**
```python
POSITIVE_CONFIRMATIONS = {
    "yes", "confirm", "evet", "onay", "y", "approve", "ok", "tamam", "go", "proceed"
}
```

Bunların dışındaki tüm yanıtlar "iptal" olarak değerlendirilir.

### 4.3 Riskli Araç Örnekleri

Aşağıdaki araçlar `requires_confirmation=True` olarak işaretlenmelidir:

- `isolate_agent` — Agent'ı ağdan kopar
- `disable_user_account` — Kullanıcı hesabı devre dışı bırakır
- `block_ip_firewall` — Güvenlik duvarında IP bloklar
- `delete_file` — Dosya siler
- `run_shell_command` — Shell komutu çalıştırır

---

## 5. Gizli Bilgi Yönetimi

### 5.1 Environment Variable Güvenliği

Tüm hassas değerler `.env` dosyasında tutulur ve Git'e commit edilmez:

```bash
# .gitignore'da mutlaka bulunmalı:
.env
*.env
*.env.local
!.env.example
```

### 5.2 Secret Üretimi

```bash
# AGENTIX_INTERNAL_API_KEY için güçlü rastgele değer üret
openssl rand -hex 32

# JWT secret için
openssl rand -base64 48

# Webhook token için
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 5.3 Production Secret Checklist

| Secret | Minimum Uzunluk | Öneri |
|---|---|---|
| `AGENTIX_INTERNAL_API_KEY` | 32 char hex | `openssl rand -hex 32` |
| `AGENTIX_JWT_SECRET` | 32 char | `openssl rand -base64 48` |
| `NEXTAUTH_SECRET` | 32 char | `openssl rand -base64 32` |
| `WAZUH_API_PASSWORD` | 16+ char | Complexity policy |
| `THEHIVE_API_KEY` | UUID tabanlı | TheHive UI'dan üret |

---

## 6. Audit ve Logging

### 6.1 Structlog Yapılandırması

Tüm güvenlik olayları structured JSON formatında loglanır:

```python
logger.info("workspace.initialized", session_id=..., owner=...)
logger.warning("orchestrator.confirmation_required", tool=...)
logger.error("auth.failed", reason="invalid_internal_key", remote_ip=...)
```

### 6.2 İzlenmesi Gereken Kritik Log Olayları

| Log Event | Anlam | Aksiyon |
|---|---|---|
| `auth.failed` | Geçersiz API key / JWT | Alert oluştur |
| `workspace.quota_exceeded` | Disk kota aşımı | Session incelemesi |
| `path_traversal_attempt` | `../` saldırısı | Anında engel + alert |
| `orchestrator.confirmation_required` | HITL tetiklendi | Teams bildirim gönderildi |
| `orchestrator.resume.approved` | Onay verildi | Araç yürütülüyor |
| `orchestrator.resume.rejected` | Red edildi | Araç iptal edildi |

### 6.3 Log Saklama

Production'da log'lar Wazuh / Elasticsearch'e gönderilmelidir:

```env
AGENTIX_LOG_LEVEL=INFO     # DEBUG sadece development'ta
```

---

## 7. Tehdit Modeli

### STRIDE Analizi

| Tehdit | Bileşen | Mevcut Kontrol | Risk |
|---|---|---|---|
| **Spoofing** | Gateway → Core | `X-Internal-Api-Key` | 🟡 Orta (network izolasyonu ile düşer) |
| **Tampering** | Webhook payload | Path token + body hash | 🟡 Orta |
| **Repudiation** | Araç çağrıları | Structlog audit trail | 🟢 Düşük |
| **Info Disclosure** | SessionWorkspace | Path traversal block + quota | 🟢 Düşük |
| **Denial of Service** | Core API | Quota enforcement | 🟡 Orta (rate limit eklenebilir) |
| **Elevation of Privilege** | HITL bypass | `requires_confirmation` + draft_history | 🟢 Düşük |

### Bilinen Riskler ve Öneriler

> [!CAUTION]
> **Yüksek Öncelikli:** `AGENTIX_INTERNAL_API_KEY` sadece pre-shared key koruması sağlar. Production'da mutual TLS (mTLS) ile güçlendirilmesi önerilir.

> [!WARNING]
> **Orta Öncelikli:** Redis'te saklanan `draft_history` şifrelenmez. Hassas ortamlarda Redis encryption-at-rest aktif edilmeli veya Redis Cluster ACL kullanılmalıdır.

> [!NOTE]
> **İyileştirme:** API Gateway katmanına rate limiting (ör. `slowapi`) eklenmesi DoS riskini azaltır.

---

## 8. Production Sertleştirme Kontrol Listesi

### Zorunlu Adımlar

- [ ] `.env` dosyasında tüm `dev-*` ve `your-*` değerleri güvenli değerlerle değiştirildi
- [ ] `AGENTIX_INTERNAL_API_KEY` en az 32 karakterli rastgele hex
- [ ] `AGENTIX_JWT_SECRET` güçlü rastgele değer
- [ ] `WAZUH_API_VERIFY_SSL=true` (production Wazuh'da)
- [ ] Gateway dışındaki tüm portlar dış ağa kapalı
- [ ] Docker network `internal: true` olarak yapılandırıldı
- [ ] TLS reverse proxy (nginx/Traefik) ile HTTPS zorunlu
- [ ] `GATEWAY_ALLOWED_ORIGINS` sadece production domain'leri içeriyor
- [ ] Log retention politikası ve Wazuh alerting kuralları aktif

### Önerilen Ek Güvenlik

- [ ] Redis AUTH password aktif (`requirepass <strong-password>`)
- [ ] Postgres kullanıcısı minimum privilege ile yapılandırıldı
- [ ] `AGENTIX_SESSION_QUOTA_MB` iş gereksinimine göre ayarlandı
- [ ] API rate limiting eklendi (ör. `slowapi`)
- [ ] Secrets rotation prosedürü dokümante edildi
- [ ] Penetration test yapıldı (yılda en az 1)

---

## İlgili Dokümanlar

- [API Reference](./api-reference.md)
- [Testing Guide](../guides/testing-guide.md)
- [Deployment Guide](../guides/deployment-guide.md)
