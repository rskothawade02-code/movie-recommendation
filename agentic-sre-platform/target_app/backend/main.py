"""FastAPI Target Application Backend with Structured JSON Logging and Chaos Endpoints."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from chaos import (
    get_current_config,
    inject_bad_config,
    inject_db_pool_exhaustion,
    inject_redis_corruption,
    reset_all_chaos,
)
from database import (
    Order,
    Product,
    flush_redis_cache,
    get_db,
    init_db_and_seed,
    redis_client,
    reset_db_pool,
)

# Configure structured logging
LOG_DIR = os.getenv("LOG_DIR", "./logs")
os.makedirs(LOG_DIR, exist_ok=True)
STRUCTURED_LOG_FILE = os.path.join(LOG_DIR, "target_backend.log")


def log_structured(level: str, msg: str, trace_id: str = "N/A", endpoint: str = "N/A", **extra: Any) -> None:
    """Format and emit a structured JSON log entry to stdout and logfile."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level.upper(),
        "service": "target-backend",
        "trace_id": trace_id,
        "endpoint": endpoint,
        "msg": msg,
        **extra,
    }
    line = json.dumps(entry)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
    try:
        with open(STRUCTURED_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    log_structured("INFO", "Initializing database and seeding product catalog...")
    init_db_and_seed()
    log_structured("INFO", "Target Backend successfully started on port 8000")
    yield
    log_structured("INFO", "Target Backend shutting down...")


app = FastAPI(
    title="Target E-Commerce Backend",
    version="1.0.0",
    description="Multi-tier microservices stack with built-in chaos endpoints for Agentic SRE evaluation.",
    lifespan=lifespan,
)

# Prometheus metrics setup
Instrumentator().instrument(app).expose(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount SRE Mission Control REST API
try:
    from sre_routes import router as sre_router
    app.include_router(sre_router)
except Exception as _e:
    print(f"Warning: SRE routes mount failed: {_e}")


# Distributed Trace ID Middleware
@app.middleware("http")
async def distributed_tracing_middleware(request: Request, call_next):
    trace_id = request.headers.get("X-Request-ID") or f"trace-{uuid.uuid4().hex[:12]}"
    request.state.trace_id = trace_id
    start_time = time.perf_counter()

    endpoint = f"{request.method} {request.url.path}"
    log_structured("INFO", f"Incoming request: {endpoint}", trace_id=trace_id, endpoint=endpoint)

    try:
        response: Response = await call_next(request)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        response.headers["X-Request-ID"] = trace_id

        level = "ERROR" if response.status_code >= 500 else ("WARN" if response.status_code >= 400 else "INFO")
        log_structured(
            level,
            f"Handled {endpoint} -> HTTP {response.status_code} ({duration_ms}ms)",
            trace_id=trace_id,
            endpoint=endpoint,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
        return response
    except Exception as exc:
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        log_structured(
            "ERROR",
            f"Unhandled exception on {endpoint}: {type(exc).__name__}: {exc}",
            trace_id=trace_id,
            endpoint=endpoint,
            error_type=type(exc).__name__,
            error_message=str(exc),
            duration_ms=duration_ms,
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": type(exc).__name__,
                "detail": str(exc),
                "trace_id": trace_id,
            },
            headers={"X-Request-ID": trace_id},
        )


# Request Models
class OrderCreateRequest(BaseModel):
    product_id: int
    quantity: int = Field(default=1, ge=1)


# Business Endpoints
@app.get("/health")
def health_check():
    """Service health inspection."""
    cfg = get_current_config()
    return {
        "status": "healthy" if cfg["CHAOS_MODE"] == "HEALTHY" else "degraded",
        "service": "target-backend",
        "chaos_mode": cfg["CHAOS_MODE"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/products")
def get_products(db: Session = Depends(get_db), request: Request = None):
    """
    Fetch all products. Results are cached in Redis.
    If Redis payload is corrupted by chaos injection, `json.loads` raises JSONDecodeError (HTTP 500).
    """
    trace_id = getattr(request.state, "trace_id", "N/A")
    cached = redis_client.get("cache:products")

    if cached:
        try:
            # If chaos injection inserted malformed JSON bytes, this throws JSONDecodeError
            products_data = json.loads(cached)
            log_structured("INFO", f"Served {len(products_data)} products from Redis cache", trace_id=trace_id, endpoint="/products")
            return {"source": "redis_cache", "products": products_data}
        except json.JSONDecodeError as jde:
            log_structured(
                "ERROR",
                f"Redis cache schema corruption: JSONDecodeError at char {jde.pos}: {jde.msg}",
                trace_id=trace_id,
                endpoint="/products",
                corrupted_preview=str(cached)[:120],
            )
            raise HTTPException(
                status_code=500,
                detail=f"Redis schema corruption in key 'cache:products': JSONDecodeError: {jde.msg}",
            ) from jde

    # Fetch from Postgres DB and cache
    try:
        products = db.query(Product).all()
        products_dict = [
            {"id": p.id, "name": p.name, "description": p.description, "price": p.price, "inventory": p.inventory}
            for p in products
        ]
        redis_client.setex("cache:products", 300, json.dumps(products_dict))
        log_structured("INFO", f"Fetched {len(products_dict)} products from database and populated Redis", trace_id=trace_id, endpoint="/products")
        return {"source": "database", "products": products_dict}
    except Exception as e:
        log_structured("ERROR", f"Failed querying products from database: {e}", trace_id=trace_id, endpoint="/products")
        raise HTTPException(status_code=500, detail=f"Database error: {e}") from e


@app.post("/orders")
def create_order(order_req: OrderCreateRequest, request: Request, db: Session = Depends(get_db)):
    """
    Place a new customer order.
    Checks simulated latency/timeout config and writes to Postgres.
    If DB connection pool is exhausted, raises QueuePool TimeoutError.
    """
    trace_id = getattr(request.state, "trace_id", "N/A")
    cfg = get_current_config()

    # 1. Enforce simulated payment gateway outage or memory pressure chaos
    if cfg.get("PAYMENT_GATEWAY_OUTAGE"):
        log_structured(
            "ERROR",
            "Downstream 3rd-party Payment Provider 503: Service Unavailable / Network drop",
            trace_id=trace_id,
            endpoint="/orders",
            error_type="PaymentGatewayUnavailable",
            error_message="Downstream payment gateway unreachable",
        )
        raise HTTPException(
            status_code=503,
            detail="Downstream Payment Provider 503: Service Unavailable",
        )

    if cfg.get("MEMORY_PRESSURE"):
        log_structured(
            "ERROR",
            "Worker thread memory threshold saturated on /orders",
            trace_id=trace_id,
            endpoint="/orders",
            error_type="WorkerMemorySaturation",
            error_message="Worker process memory exceeded safe 90% threshold",
        )
        raise HTTPException(
            status_code=500,
            detail="Internal Server Error: Worker memory limit saturated",
        )

    # 2. Enforce simulated payment gateway timeout / latency chaos
    latency = cfg.get("SIMULATED_LATENCY_SECONDS", 0.0)
    timeout_limit = cfg.get("PAYMENT_GATEWAY_TIMEOUT", 5.0)

    if latency > 0:
        time.sleep(latency)
        if latency > timeout_limit:
            log_structured(
                "ERROR",
                f"Payment gateway timeout: execution {latency}s exceeded limit {timeout_limit}s",
                trace_id=trace_id,
                endpoint="/orders",
                timeout_limit=timeout_limit,
                latency=latency,
            )
            raise HTTPException(
                status_code=504,
                detail=f"Gateway Timeout: External payment gateway latency ({latency}s) exceeded timeout ({timeout_limit}s)",
            )

    # 2. Database transaction (will fail with TimeoutError if pool is exhausted)
    try:
        product = db.query(Product).filter(Product.id == order_req.product_id).first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        total = round(product.price * order_req.quantity, 2)
        order = Order(
            product_id=order_req.product_id,
            quantity=order_req.quantity,
            total_price=total,
            trace_id=trace_id,
        )
        db.add(order)
        db.commit()
        db.refresh(order)

        log_structured(
            "INFO",
            f"Created Order #{order.id} for Product {product.name} (Total: ${total})",
            trace_id=trace_id,
            endpoint="/orders",
            order_id=order.id,
            total=total,
        )
        return {
            "status": "order_confirmed",
            "order_id": order.id,
            "product_name": product.name,
            "quantity": order_req.quantity,
            "total_price": total,
            "trace_id": trace_id,
        }
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        err_type = type(exc).__name__
        log_structured(
            "ERROR",
            f"Database operation failed on /orders: {err_type}: {exc}",
            trace_id=trace_id,
            endpoint="/orders",
            error_type=err_type,
            error_message=str(exc),
        )
        raise HTTPException(status_code=500, detail=f"Database transaction failure: {err_type}: {exc}") from exc


# Chaos Injection Control Endpoints
@app.post("/chaos/db-pool-exhaust")
def endpoint_chaos_db_pool(request: Request):
    """Trigger DB connection pool exhaustion failure."""
    trace_id = getattr(request.state, "trace_id", "N/A")
    res = inject_db_pool_exhaustion()
    log_structured("WARN", "Chaos injected: db-pool-exhaust", trace_id=trace_id, endpoint="/chaos/db-pool-exhaust")
    return res


@app.post("/chaos/redis-corrupt")
def endpoint_chaos_redis_corrupt(request: Request):
    """Trigger Redis cache malformed JSON schema corruption."""
    trace_id = getattr(request.state, "trace_id", "N/A")
    res = inject_redis_corruption()
    log_structured("WARN", "Chaos injected: redis-corrupt", trace_id=trace_id, endpoint="/chaos/redis-corrupt")
    return res


@app.post("/chaos/bad-config")
def endpoint_chaos_bad_config(request: Request):
    """Trigger bad payment gateway timeout / latency configuration."""
    trace_id = getattr(request.state, "trace_id", "N/A")
    res = inject_bad_config()
    log_structured("WARN", "Chaos injected: bad-config", trace_id=trace_id, endpoint="/chaos/bad-config")
    return res


# Remediation / Admin Healing Endpoints
@app.post("/admin/reset-db-pool")
def endpoint_reset_db_pool():
    """Remediation tool endpoint to dispose and reset DB connection pool."""
    from chaos import _LEAKED_CONNECTIONS, _ACTIVE_CONFIG
    for conn in _LEAKED_CONNECTIONS:
        try:
            conn.close()
        except Exception:
            pass
    _LEAKED_CONNECTIONS.clear()
    res = reset_db_pool()
    _ACTIVE_CONFIG["CHAOS_MODE"] = "HEALTHY"
    return res


@app.post("/admin/reset-config")
def endpoint_reset_config():
    """Remediation tool endpoint to restore default operational config."""
    res = reset_all_chaos()
    return res


@app.post("/admin/flush-cache")
def endpoint_flush_cache():
    """Remediation tool endpoint to clear corrupted Redis keys."""
    from chaos import _ACTIVE_CONFIG
    res = flush_redis_cache()
    _ACTIVE_CONFIG["CHAOS_MODE"] = "HEALTHY"
    return res


@app.post("/admin/failover-gateway")
def endpoint_failover_gateway():
    """Remediation tool endpoint to activate payment circuit breaker & failover."""
    from chaos import _ACTIVE_CONFIG
    _ACTIVE_CONFIG["PAYMENT_GATEWAY_OUTAGE"] = False
    _ACTIVE_CONFIG["CHAOS_MODE"] = "HEALTHY"
    return {"status": "success", "action": "failover_payment_gateway", "detail": "Payment circuit breaker activated. Fallback processor engaged."}


@app.post("/admin/recycle-workers")
def endpoint_recycle_workers():
    """Remediation tool endpoint to purge memory pressure buffers."""
    from chaos import _ACTIVE_CONFIG, _MEMORY_LEAK_BUFFER
    import gc
    _MEMORY_LEAK_BUFFER.clear()
    gc.collect()
    _ACTIVE_CONFIG["MEMORY_PRESSURE"] = False
    _ACTIVE_CONFIG["CHAOS_MODE"] = "HEALTHY"
    return {"status": "success", "action": "recycle_worker_threads", "detail": "Memory buffers purged and worker state refreshed."}


@app.post("/admin/reset-all")
def endpoint_reset_all():
    """Full system reset to healthy state."""
    res = reset_all_chaos()
    return res
