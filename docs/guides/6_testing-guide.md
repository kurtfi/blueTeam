# Testing Guide

Agentix / BlueTeam platformu için kapsamlı test rehberi.
Bu doküman test yapısını, her katmanın nasıl çalıştırıldığını ve yeni testlerin nasıl yazılacağını açıklar.

---

## Test Mimarisi

```
tests/
├── unit/                          # Hızlı, izole, saf birim testleri
│   ├── test_agentic_common/       # AgenticCommon katmanı
│   │   ├── test_embeddings.py
│   │   ├── test_preferences.py
│   │   ├── test_redis_preferences.py
│   │   └── test_redis_store.py
│   ├── test_agentix/              # Core Agentix davranışları
│   │   ├── test_alert_dedup.py
│   │   ├── test_cleanup.py
│   │   ├── test_draft_history.py
│   │   ├── test_executor.py
│   │   ├── test_gateway_auth.py
│   │   ├── test_gateway_webhooks.py
│   │   ├── test_gemini_provider.py
│   │   ├── test_langfuse_conn.py
│   │   ├── test_mcp_adapter.py
│   │   ├── test_ollama_provider.py
│   │   ├── test_triage_workflow.py
│   │   └── test_workspace.py
│   └── test_triagecore/           # TriageCore / Playbook motoru
│       ├── test_playbook_resolution.py
│       └── test_soc_tools.py
└── integration/                   # Dış bağımlılıklar gerektiren entegrasyon testleri
    └── conftest.py
```

### Bağımlılık Katmanları

| Katman | Kapsam | Bağımlılık |
|---|---|---|
| **Unit** | Pure Python logic, mock-tabanlı | Yok (in-memory) |
| **Integration** | Redis, Postgres, Wazuh | Çalışan servisler |
| **E2E** | Uçtan uca API akışları | Tam docker-compose stack |

---

## Kurulum

### Gereksinimler

```bash
# Python bağımlılıklarını yükle (test extras dahil)
pip install -e "src/Agentix[test]"
pip install -e "src/TriageCore[test]"
pip install -e "src/AgenticCommon[test]"

# Ya da tek seferinde:
pip install pytest pytest-asyncio pytest-mock
```

### `pytest.ini` Yapılandırması

Proje kökündeki `pytest.ini` zaten gerekli yolları yapılandırıyor:

```ini
[pytest]
asyncio_mode = auto
asyncio_default_fixture_loop_scope = function
pythonpath =
    src/Agentix
    src/TriageCore
    src/AgenticCommon
testpaths =
    tests
```

---

## Testleri Çalıştırma

### Tüm Birim Testleri

```bash
# Proje kökünden çalıştır
pytest tests/unit/ -v
```

### Belirli Bir Modülün Testleri

```bash
# Agentix modülü
pytest tests/unit/test_agentix/ -v

# TriageCore / Playbook motoru
pytest tests/unit/test_triagecore/ -v

# AgenticCommon yardımcıları
pytest tests/unit/test_agentic_common/ -v
```

### Belirli Bir Test Dosyası veya Fonksiyon

```bash
# Tek dosya
pytest tests/unit/test_agentix/test_workspace.py -v

# Tek test fonksiyonu
pytest tests/unit/test_agentix/test_workspace.py::test_resolve_path_traversal_blocked -v
```

### Yavaş/IO Testlerini Atla (Hızlı CI Modu)

```bash
pytest tests/unit/ -v -m "not slow"
```

### Test Kapsamı Raporu

```bash
pytest tests/unit/ --cov=src --cov-report=term-missing --cov-report=html
# Rapor: htmlcov/index.html
```

---

## Birim Test Detayları

### SessionWorkspace Testleri (`test_workspace.py`)

Workspace katmanının güvenlik ve izolasyon davranışlarını kapsar.

**Fixture Yapısı:**

```python
@pytest.fixture
def workspace_root(tmp_path: Path):
    """tmp_path kullanarak gerçek disk I/O'su izole edilir."""
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()
    from agentic_common import settings as settings_mod
    # Ayarlar monkey-patch edilir, test sonrası geri alınır
    original_root = settings_mod.settings.agentix_session_workspace_root
    settings_mod.settings.agentix_session_workspace_root = str(sessions_dir)
    yield sessions_dir
    settings_mod.settings.agentix_session_workspace_root = original_root
```

**Kapsanan Senaryolar:**

| Test | Doğrulanan Davranış |
|---|---|
| `test_initialize_creates_directory_tree` | `downloads/`, `outputs/`, `uploads/`, `temp/` oluşturulur |
| `test_resolve_path_traversal_blocked` | `../../etc/passwd` girişimi `PermissionError` fırlatır |
| `test_validate_access_matches_owner` | Farklı `owner_id` erişimi reddeder |
| `test_check_quota_fails_when_exceeded` | 2 MB yazma girişimi 1 MB kotada başarısız olur |
| `test_cleanup_deletes_temp_and_downloads_keeps_outputs` | `outputs/` dosyaları korunur |
| `test_destroy_removes_entire_workspace` | Root dizin tamamen silinir |
| `test_from_session_id_reconstructs_workspace` | Disk'ten `owner_id` okuyarak yeniden oluşturur |

### Playbook Çözümleme Testleri (`test_playbook_resolution.py`)

Playbook step şablonlama motorunu doğrular.

```python
def test_interpolate_string():
    ctx = PlaybookContext(alert={"agent_id": "007", "src_ip": "10.0.0.99"})
    step = PlaybookStep(order=0, title="Test", description="Isolate ctx.agent_id", group="Investigation")
    assert step._interpolate_string("IP is ctx.src_ip", ctx) == "IP is 10.0.0.99"
```

**Kapsanan Senaryolar:**

| Test | Doğrulanan Davranış |
|---|---|
| `test_interpolate_string` | `ctx.field` → gerçek değer dönüşümü |
| `test_render_instruction_with_deep_resolution` | `ctx.alert.username`, ApprovalGate interpolasyonu |

### Gateway Auth Testleri (`test_gateway_auth.py`)

`X-Internal-Api-Key` header doğrulama akışını kapsar.

### MCP Adapter Testleri (`test_mcp_adapter.py`)

TriageCore MCP arayüzünün araç kayıt ve çağırma protokolünü doğrular.

---

## Entegrasyon Testleri

Entegrasyon testleri **çalışan dış servislere** ihtiyaç duyar.

### Ön Koşullar

```bash
# Gerekli servisleri kaldır
docker-compose up -d redis postgres
```

### Bağlayıcı Önbellek İzolasyonu

`tests/integration/conftest.py` her test sonrasında tüm bağlayıcı önbelleklerini temizler:

```python
@pytest.fixture(autouse=True)
async def clear_connector_caches():
    yield  # test çalışır
    # SQL, MongoDB, Redis, Elasticsearch, Neo4j önbellekleri temizlenir
    from general_mcp.tools.data.connectors.data_server import _sql_engines
    _sql_engines.clear()
    # ... diğer bağlayıcılar
```

Bu fixture `autouse=True` olduğundan tüm entegrasyon testlerinde **otomatik** çalışır.

### Entegrasyon Testlerini Çalıştırma

```bash
# Gerçek servislerle
REDIS_URL=redis://localhost:6379 \
POSTGRES_DSN=postgresql://agentix:agentix@localhost:5432/agentix_db \
pytest tests/integration/ -v
```

---

## Yeni Test Yazma Rehberi

### Birim Testi Şablonu (Async)

```python
"""
test_my_feature.py — MyFeature birim testleri
"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_my_feature_happy_path():
    """Normal akışın beklenen çıktıyı ürettiğini doğrular."""
    # Arrange
    from agentix.my_module import MyFeature
    feature = MyFeature()

    # Act
    result = await feature.do_something(input_data="test")

    # Assert
    assert result.success is True
    assert result.output == "expected"


@pytest.mark.asyncio
async def test_my_feature_error_handling():
    """Hatalı girişin uygun exception fırlattığını doğrular."""
    from agentix.my_module import MyFeature
    feature = MyFeature()

    with pytest.raises(ValueError, match="invalid input"):
        await feature.do_something(input_data=None)
```

### Mock Kullanımı

```python
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_with_mocked_llm():
    with patch("agentix.core.llm.LLMClient.chat", new_callable=AsyncMock) as mock_chat:
        mock_chat.return_value = {"content": "Final Answer: success"}
        # test devam eder
```

### Fixture Paylaşımı

Ortak fixture'ları `conftest.py` içine koy:

```python
# tests/unit/conftest.py
import pytest

@pytest.fixture
def sample_alert():
    return {
        "agent_id": "001",
        "agent_name": "test-agent",
        "src_ip": "192.168.1.100",
        "username": "test_user",
        "rule_description": "Test alert"
    }
```

---

## CI/CD Entegrasyonu

### GitHub Actions Örneği

```yaml
name: Unit Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          pip install -e "src/Agentix[test]"
          pip install -e "src/TriageCore[test]"
          pip install -e "src/AgenticCommon[test]"

      - name: Run unit tests
        run: pytest tests/unit/ -v --tb=short

      - name: Coverage report
        run: pytest tests/unit/ --cov=src --cov-report=xml
```

---

## Sorun Giderme

### `ModuleNotFoundError` Hatası

`pytest.ini` içinde `pythonpath` doğru yapılandırıldığından emin ol:

```ini
pythonpath =
    src/Agentix
    src/TriageCore
    src/AgenticCommon
```

Alternatif olarak:
```bash
PYTHONPATH=src/Agentix:src/TriageCore:src/AgenticCommon pytest tests/unit/ -v
```

### Async Test Hatası

`pytest-asyncio` yüklü olduğundan emin ol ve `asyncio_mode = auto` ayarlandığından emin ol.

```bash
pip install pytest-asyncio
```

### Bağlayıcı Önbellek Kirliliği

Entegrasyon testlerinde beklenmedik davranış görüyorsan:

```bash
# Testleri izole çalıştır
pytest tests/integration/ -v --forked
```

---

## İlgili Dokümanlar

- [API Reference](../architecture/api-reference.md)
- [Playbook Development Guide](./5_playbook-development.md)
- [Security Model](../architecture/security-model.md)
