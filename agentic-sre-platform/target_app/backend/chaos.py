"""Controlled failure injection module for SRE chaos engineering testing."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from database import engine, redis_client

logger = logging.getLogger("target_app.chaos")

# State holders for active chaos scenarios
_LEAKED_CONNECTIONS: list[Any] = []
_MEMORY_LEAK_BUFFER: list[bytes] = []
_ACTIVE_CONFIG: dict[str, Any] = {
    "PAYMENT_GATEWAY_TIMEOUT": 5.0,
    "PAYMENT_GATEWAY_ENABLED": True,
    "PAYMENT_GATEWAY_OUTAGE": False,
    "SIMULATED_LATENCY_SECONDS": 0.0,
    "MEMORY_PRESSURE": False,
    "CHAOS_MODE": "HEALTHY",
}


def get_current_config() -> dict[str, Any]:
    """Retrieve current operational runtime configuration."""
    return dict(_ACTIVE_CONFIG)


def inject_db_pool_exhaustion(count: int = 20) -> dict[str, Any]:
    """
    Open and intentionally retain connections without returning them to the pool.
    With pool_size=5 and max_overflow=10, acquiring 15+ connections exhausts the pool,
    causing subsequent requests to fail with QueuePool timeout.
    """
    global _LEAKED_CONNECTIONS
    _ACTIVE_CONFIG["CHAOS_MODE"] = "DB_POOL_EXHAUSTED"
    leaked_this_call = 0

    for i in range(count):
        try:
            conn = engine.connect()
            _LEAKED_CONNECTIONS.append(conn)
            leaked_this_call += 1
        except Exception as e:
            logger.error("DB connection pool limit reached while exhausting: %s", e)
            break

    logger.warning(
        "Chaos injected: DB connection pool exhausted. Leaked %d connections (total leaked: %d).",
        leaked_this_call,
        len(_LEAKED_CONNECTIONS),
    )
    return {
        "scenario": "db-pool-exhaust",
        "status": "injected",
        "total_leaked_connections": len(_LEAKED_CONNECTIONS),
        "detail": "SQLAlchemy pool saturated. Subsequent DB queries will time out.",
    }


def inject_redis_corruption() -> dict[str, Any]:
    """
    Writes malformed non-JSON string bytes into the products cache key.
    Any subsequent `GET /products` attempting `json.loads` will raise JSONDecodeError.
    """
    _ACTIVE_CONFIG["CHAOS_MODE"] = "REDIS_CORRUPTED"
    corrupted_payload = "{\"products\": [{\"id\": 1, \"name\": \"SRE Handbook\", CORRUPTED_BYTES_0xDEADBEEF..."
    redis_client.set("cache:products", corrupted_payload)
    logger.warning("Chaos injected: Corrupted malformed payload written to Redis key 'cache:products'.")
    return {
        "scenario": "redis-corrupt",
        "status": "injected",
        "key": "cache:products",
        "detail": "Malformed JSON payload stored in Redis. Cache reads will raise JSONDecodeError.",
    }


def inject_bad_config() -> dict[str, Any]:
    """
    Simulates a bad feature-flag / configuration deployment where PAYMENT_GATEWAY_TIMEOUT
    is set to an impossible 0.001 seconds (1ms) with an enforced delay, causing downstream timeouts.
    """
    _ACTIVE_CONFIG["PAYMENT_GATEWAY_TIMEOUT"] = 0.001
    _ACTIVE_CONFIG["SIMULATED_LATENCY_SECONDS"] = 2.5
    _ACTIVE_CONFIG["CHAOS_MODE"] = "BAD_CONFIG_LATENCY"
    logger.warning(
        "Chaos injected: Bad configuration applied (PAYMENT_GATEWAY_TIMEOUT=0.001s, LATENCY=2.5s)."
    )
    return {
        "scenario": "bad-config",
        "status": "injected",
        "config": dict(_ACTIVE_CONFIG),
        "detail": "Payment timeout reduced to 1ms with artificial delay. Order processing will cascade into 504/500.",
    }


def inject_payment_outage() -> dict[str, Any]:
    """
    Simulates third-party payment partner outage returning HTTP 503 Service Unavailable.
    """
    _ACTIVE_CONFIG["PAYMENT_GATEWAY_OUTAGE"] = True
    _ACTIVE_CONFIG["CHAOS_MODE"] = "PAYMENT_GATEWAY_OUTAGE"
    logger.warning("Chaos injected: Downstream payment provider outage enabled.")
    return {
        "scenario": "payment-outage",
        "status": "injected",
        "detail": "Third-party payment gateway unreachable. Checkout returns 503.",
    }


def inject_memory_pressure() -> dict[str, Any]:
    """
    Simulates memory leak / worker thread saturation.
    """
    global _MEMORY_LEAK_BUFFER
    _ACTIVE_CONFIG["MEMORY_PRESSURE"] = True
    _ACTIVE_CONFIG["CHAOS_MODE"] = "MEMORY_PRESSURE"
    # Allocate memory chunks
    for _ in range(5):
        _MEMORY_LEAK_BUFFER.append(b"X" * (1024 * 1024 * 10))  # 50MB
    logger.warning("Chaos injected: Memory pressure buffer allocated.")
    return {
        "scenario": "memory-pressure",
        "status": "injected",
        "detail": "Worker memory pressure & queue saturation injected.",
    }


def reset_all_chaos() -> dict[str, Any]:
    """Restore all chaos injectors back to healthy operational baseline."""
    global _LEAKED_CONNECTIONS, _MEMORY_LEAK_BUFFER, _ACTIVE_CONFIG
    closed_count = 0
    for conn in _LEAKED_CONNECTIONS:
        try:
            conn.close()
            closed_count += 1
        except Exception:
            pass
    _LEAKED_CONNECTIONS.clear()
    _MEMORY_LEAK_BUFFER.clear()
    engine.dispose()

    try:
        redis_client.flushdb()
    except Exception:
        pass

    _ACTIVE_CONFIG["PAYMENT_GATEWAY_TIMEOUT"] = 5.0
    _ACTIVE_CONFIG["PAYMENT_GATEWAY_ENABLED"] = True
    _ACTIVE_CONFIG["PAYMENT_GATEWAY_OUTAGE"] = False
    _ACTIVE_CONFIG["SIMULATED_LATENCY_SECONDS"] = 0.0
    _ACTIVE_CONFIG["MEMORY_PRESSURE"] = False
    _ACTIVE_CONFIG["CHAOS_MODE"] = "HEALTHY"

    logger.info("Chaos reset: Closed %d leaked connections, flushed Redis, restored defaults.", closed_count)
    return {
        "status": "healthy_baseline_restored",
        "closed_connections": closed_count,
        "config": dict(_ACTIVE_CONFIG),
    }
