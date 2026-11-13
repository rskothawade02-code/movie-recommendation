# SRE Incident Operational Runbooks

This knowledge base provides standard operating procedures (SOPs), diagnostic criteria, and safe remediation tools for production incidents in the E-Commerce Microservices stack.

---

## Runbook 001: Database Connection Pool Exhaustion

- **Incident Signature:** `QueuePool limit of size 5 overflow 10 reached` or `TimeoutError` acquiring connection from SQLAlchemy engine.
- **Affected Services:** `target-backend`, `target-postgres`
- **Impacted Endpoints:** `POST /orders`, `POST /checkout`
- **Root Cause Analysis:**
  Occurs when transactions or exception paths fail to release connections back to the `SessionLocal` pool, or unclosed query sessions accumulate. This exhausts the 5 connection pool plus 10 overflow limit, blocking all subsequent customer checkout operations with HTTP 500.
- **Diagnostic Commands / Telemetry:**
  - Check `target-backend` logs for `TimeoutError` or `QueuePool`.
  - Check active connections on Postgres: `SELECT count(*) FROM pg_stat_activity;`.
- **Approved Remediation Actions:**
  - **Action 1 (In-Process):** Call `reset_db_pool()` via `POST /admin/reset-db-pool`. This disposes the dead pool and reinitializes fresh connection handles.
  - **Action 2 (Container Level):** If the service is completely unresponsive, execute `restart_container("target-backend")`.
- **Verification Criteria:**
  - Verify `POST /orders` returns HTTP 200 OK with `order_confirmed`.
  - Verify error rate on `/metrics` drops back to 0.00%.

---

## Runbook 002: Redis Cache Schema Corruption

- **Incident Signature:** `JSONDecodeError` or `TypeError: the JSON object must be str, bytes or bytearray` on Redis key reads.
- **Affected Services:** `target-backend`, `target-redis`
- **Impacted Endpoints:** `GET /products`
- **Root Cause Analysis:**
  A bad serialization deployment, data migration script, or byte corruption wrote non-parseable payload into `cache:products`. When `target-backend` reads the key and calls `json.loads(cached)`, Python raises `json.decoder.JSONDecodeError`, causing an unhandled HTTP 500 error.
- **Diagnostic Commands / Telemetry:**
  - Check `target-backend` logs for `Redis cache schema corruption` or `JSONDecodeError`.
  - Inspect key via Redis CLI: `redis-cli GET cache:products`.
- **Approved Remediation Actions:**
  - **Action 1 (In-Process):** Call `flush_redis_cache()` via `POST /admin/flush-cache` or delete key `cache:products`.
  - **Action 2 (Container Level):** Call `restart_container("target-redis")`.
- **Verification Criteria:**
  - Query `GET /products` and ensure response returns HTTP 200 OK with valid product array from Postgres fallback.

---

## Runbook 003: API Latency & Payment Gateway Timeout Cascade

- **Incident Signature:** HTTP 504 Gateway Timeout, `PAYMENT_GATEWAY_TIMEOUT` exceeded, or latency p99 > 2,000ms.
- **Affected Services:** `target-frontend`, `target-backend`
- **Impacted Endpoints:** `POST /orders`
- **Root Cause Analysis:**
  A bad environment variable or configuration push lowered `PAYMENT_GATEWAY_TIMEOUT` below standard external roundtrip latency (e.g. 0.001s / 1ms), or external upstream latency degraded, causing the frontend and backend to time out waiting for payment confirmation.
- **Diagnostic Commands / Telemetry:**
  - Inspect backend config via `GET /health`.
  - Check `target-backend` logs for `Payment gateway timeout: execution ... exceeded limit`.
- **Approved Remediation Actions:**
  - **Action 1 (In-Process):** Call `revert_bad_config()` via `POST /admin/reset-config` to restore `PAYMENT_GATEWAY_TIMEOUT=5.0` and clear artificial delay.
  - **Action 2 (Container Level):** Roll back container environment variables and execute `restart_container("target-backend")`.
- **Verification Criteria:**
  - Latency on `POST /orders` returns to < 50ms and HTTP 200 OK confirms order.
