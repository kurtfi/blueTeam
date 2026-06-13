"""
Application settings loaded from environment variables.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LLM
    agentix_llm_provider: str = "ollama"  # openai | gemini | ollama
    agentix_embedding_provider: str = "ollama"  # ollama | openai
    agentix_vector_store: str = "inmemory"  # inmemory | postgres
    agentix_postgres_url: str = "postgresql+asyncpg://agentix:password@localhost:25432/agentix_db"

    # OpenAI Settings
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"

    # Gemini Settings
    gemini_api_key: str = ""
    gemini_model: str = "gemini-1.5-pro"

    # Ollama Settings
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3.5:9b"
    ollama_embedding_model: str = "nomic-embed-text"

    # Security — Internal API Key for Gateway ↔ Core communication.
    # Set via AGENTIX_INTERNAL_API_KEY env var. If empty, internal auth is disabled (dev only).
    agentix_internal_api_key: str = ""

    # Orchestrator
    agentix_max_iterations: int = 10
    agentix_sandbox_enabled: bool = True
    agentix_log_level: str = "INFO"
    # Workspace root — used by FileManager as the SAFE_ROOT for path containment.
    # Defaults to the current working directory; override via AGENTIX_WORKSPACE_ROOT env var.
    agentix_workspace_root: str = ""
    # RAG — native context injection into the system prompt (no tool call required).
    agentix_rag_enabled: bool = True
    agentix_rag_top_k: int = 5
    agentix_triage_core_url: str = "http://localhost:8081/sse"
    agentix_attack_simulator_url: str = "http://localhost:8082/sse"

    # Session Workspace — per-session isolated file storage
    agentix_session_workspace_enabled: bool = True
    agentix_session_workspace_root: str = ""  # Empty → defaults to WORKSPACE_ROOT/sessions
    agentix_session_quota_mb: int = 100  # Max disk per session (MB), 0 = unlimited
    agentix_session_ttl_hours: int = 24  # Session workspace TTL before cleanup
    agentix_session_cleanup_on_expire: bool = True  # Auto-clean temp/downloads on expire
    agentix_session_destroy_on_expire: bool = False  # Full destroy after grace period

    # Memory
    agentix_memory_backend: str = "inmemory"  # inmemory | redis | postgres
    redis_url: str = "redis://localhost:26379"
    # SQL Databases
    agentix_sql_databases: dict[str, str] = {
        "default": "postgresql+asyncpg://agentix:password@localhost:25432/agentix_db",
        "mysql": "mysql+aiomysql://agentix:password@localhost:3306/agentix_db",
    }

    # NoSQL Databases
    agentix_mongodb_databases: dict[str, str] = {
        "default": "mongodb://agentix:password@localhost:27017/agentix_db?authSource=admin"
    }
    agentix_elasticsearch_databases: dict[str, str] = {"default": "http://localhost:9200"}
    agentix_redis_databases: dict[str, str] = {"default": "redis://localhost:26379"}
    agentix_neo4j_databases: dict[str, str] = {"default": "bolt://localhost:7687"}

    # Mail provider: "smtp" or "sendgrid"
    agentix_mail_provider: str = "smtp"
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "agentix@test.local"
    sendgrid_api_key: str = ""

    # Messaging providers
    telegram_bot_token: str = ""
    slack_bot_token: str = ""
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_from_number: str = ""
    twilio_whatsapp_from: str = ""

    # Langfuse Observability
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_host: str = "http://localhost:3010"
    langfuse_enabled: bool = False


settings = Settings()
