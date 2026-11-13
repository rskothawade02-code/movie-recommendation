"""Database and Redis cache connection module with pooling and resilience."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Generator

import redis
from sqlalchemy import Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger("target_app.database")

# Environment configuration with safe local fallbacks
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sre_user:sre_password@target-postgres:5432/sre_db")
REDIS_URL = os.getenv("REDIS_URL", "redis://target-redis:6379/0")

# Handle SQLite fallback for local running if Postgres unavailable
try:
    engine = create_engine(
        DATABASE_URL,
        pool_size=5,
        max_overflow=10,
        pool_timeout=3.0,
        pool_recycle=1800,
    )
    # Test connection
    with engine.connect() as conn:
        pass
except Exception as e:
    logger.warning("Postgres connection failed (%s), falling back to local SQLite", e)
    DATABASE_URL = "sqlite:///./target_app.db"
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        pool_size=5,
        max_overflow=10,
        pool_timeout=3.0,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Models
class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(String(1000), default="")
    price = Column(Float, nullable=False)
    inventory = Column(Integer, default=100)


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(Integer, nullable=False)
    quantity = Column(Integer, default=1)
    total_price = Column(Float, nullable=False)
    trace_id = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# Redis Client with fallback
try:
    redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=2.0)
    redis_client.ping()
except Exception as e:
    logger.warning("Redis connection failed (%s), falling back to in-memory dictionary proxy", e)

    class InMemoryRedis:
        def __init__(self):
            self.store = {}

        def get(self, key):
            return self.store.get(key)

        def set(self, key, val, ex=None):
            self.store[key] = val
            return True

        def setex(self, key, time_s, val):
            self.store[key] = val
            return True

        def flushdb(self):
            self.store.clear()
            return True

        def ping(self):
            return True

    redis_client = InMemoryRedis()  # type: ignore


def init_db_and_seed() -> None:
    """Create tables and seed initial inventory."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(Product).count() == 0:
            sample_products = [
                Product(name="SRE Incident Response Handbook", description="Production post-mortems and runbooks guide", price=49.99, inventory=250),
                Product(name="Ultra-Low-Latency Tracing Proxy", description="Enterprise eBPF observability agent license", price=299.00, inventory=80),
                Product(name="Mechanical Keyboard (SRE Edition)", description="Ergonomic tactile switches for fast terminal typing", price=149.50, inventory=120),
                Product(name="Dual-Port 100GbE NIC Card", description="High-throughput datacenter network adapter", price=450.00, inventory=45),
                Product(name="High-Performance GPU Cluster Node", description="PCIe Gen5 AI inference accelerator", price=1850.00, inventory=15),
                Product(name="Site Reliability Engineering Cap", description="Wearable badge of honor for 99.999% uptime", price=24.00, inventory=300),
            ]
            db.add_all(sample_products)
            db.commit()
            logger.info("Seeded %d initial products into database", len(sample_products))
    finally:
        db.close()


# Auto-ensure tables on module load
try:
    init_db_and_seed()
except Exception as _e:
    logger.warning("Initial table seed skipped (%s)", _e)


def get_db() -> Generator:
    """Dependency for acquiring DB sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def reset_db_pool() -> dict[str, str]:
    """Force-dispose the SQLAlchemy connection pool and create a clean one."""
    global engine, SessionLocal
    engine.dispose()
    logger.info("SQLAlchemy connection pool explicitly disposed and refreshed")
    return {"status": "pool_recreated", "pool_size": 5, "max_overflow": 10}


def flush_redis_cache() -> dict[str, str]:
    """Flush Redis keys to restore clean cache state."""
    redis_client.flushdb()
    logger.info("Redis cache flushed successfully")
    return {"status": "cache_flushed"}
