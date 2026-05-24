import asyncio
import random
from typing import Any
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from motor.motor_asyncio import AsyncIOMotorClient
from elasticsearch import AsyncElasticsearch
from neo4j import AsyncGraphDatabase
import redis.asyncio as redis
from agentic_common.settings import settings

class DatabaseSeeder:
    def __init__(self):
        self.settings = settings

    async def seed_postgres(self):
        print("🌱 Seeding PostgreSQL...")
        dsn = self.settings.agentix_sql_databases["default"]
        engine = create_async_engine(dsn)
        async with engine.begin() as conn:
            # Enable pgvector if available
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
            await conn.execute(text("DROP TABLE IF EXISTS users CASCADE;"))
            await conn.execute(text("""
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """))
            await conn.execute(text("""
                INSERT INTO users (name, email) VALUES
                ('Alice', 'alice@example.com'),
                ('Bob', 'bob@example.com'),
                ('Charlie', 'charlie@example.com');
            """))
        await engine.dispose()
        print("✅ PostgreSQL seeded.")

    async def seed_mysql(self):
        print("🌱 Seeding MySQL...")
        dsn = self.settings.agentix_sql_databases["mysql"]
        engine = create_async_engine(dsn)
        async with engine.begin() as conn:
            await conn.execute(text("DROP TABLE IF EXISTS products;"))
            await conn.execute(text("""
                CREATE TABLE products (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    sku VARCHAR(255) UNIQUE NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    price DECIMAL(10, 2) NOT NULL
                );
            """))
            await conn.execute(text("""
                INSERT INTO products (sku, name, price) VALUES
                ('LAP-001', 'High-end Laptop', 1200.50),
                ('PHN-002', 'Smartphone Ultra', 899.99),
                ('MOU-003', 'Wireless Mouse', 24.95);
            """))
        await engine.dispose()
        print("✅ MySQL seeded.")

    async def seed_mongodb(self):
        print("🌱 Seeding MongoDB...")
        dsn = self.settings.agentix_mongodb_databases["default"]
        client = AsyncIOMotorClient(dsn)
        db = client.get_database()
        
        # Clear collection
        await db.logs.drop()
        
        logs = [
            {"level": "INFO", "message": "System started", "timestamp": "2024-01-01T10:00:00Z"},
            {"level": "WARNING", "message": "High disk usage", "timestamp": "2024-01-01T12:30:00Z"},
            {"level": "ERROR", "message": "Database connection failed", "timestamp": "2024-01-02T08:15:00Z"},
        ]
        await db.logs.insert_many(logs)
        client.close()
        print("✅ MongoDB seeded.")

    async def seed_elasticsearch(self):
        print("🌱 Seeding Elasticsearch...")
        dsn = self.settings.agentix_elasticsearch_databases["default"]
        client = AsyncElasticsearch(dsn)
        
        index_name = "articles"
        try:
            if await client.indices.exists(index=index_name):
                await client.indices.delete(index=index_name)
            
            await client.indices.create(index=index_name)
            
            articles = [
                {"title": "The Rise of AI Agents", "content": "How autonomous agents are changing the world."},
                {"title": "FastMCP Explained", "content": "A guide to building MCP servers efficiently."},
                {"title": "Vector Databases in 2024", "content": "Why every RAG pipeline needs one."},
            ]
            
            for i, article in enumerate(articles):
                await client.index(index=index_name, id=str(i), document=article)
                
            await client.indices.refresh(index=index_name)
        except Exception as e:
            print(f"⚠️ Elasticsearch seeding warning: {e}")
        finally:
            await client.close()
        print("✅ Elasticsearch seeded.")

    async def seed_neo4j(self):
        print("🌱 Seeding Neo4j...")
        dsn = self.settings.agentix_neo4j_databases["default"]
        user = "neo4j"
        password = "password"
        
        driver = AsyncGraphDatabase.driver(dsn, auth=(user, password))
        async with driver.session() as session:
            await session.run("MATCH (n) DETACH DELETE n")
            await session.run("""
                CREATE (a:Person {name: 'Alice'})
                CREATE (b:Person {name: 'Bob'})
                CREATE (c:Person {name: 'Charlie'})
                CREATE (a)-[:FOLLOWS]->(b)
                CREATE (b)-[:FOLLOWS]->(c)
                CREATE (c)-[:FOLLOWS]->(a)
            """)
        await driver.close()
        print("✅ Neo4j seeded.")

    async def seed_redis(self):
        print("🌱 Seeding Redis...")
        dsn = self.settings.agentix_redis_databases["default"]
        client = redis.from_url(dsn)
        
        await client.flushall()
        await client.set("system_status", "healthy")
        await client.hset("user:1:profile", mapping={"name": "Alice", "theme": "dark"})
        await client.lpush("tasks:pending", "email_notification", "data_sync", "image_render")
        
        await client.aclose()
        print("✅ Redis seeded.")

    async def run_all(self):
        tasks = [
            self.seed_postgres(),
            self.seed_mysql(),
            self.seed_mongodb(),
            self.seed_elasticsearch(),
            self.seed_neo4j(),
            self.seed_redis(),
        ]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    seeder = DatabaseSeeder()
    asyncio.run(seeder.run_all())
