"""Streamlit E-Commerce Storefront with Distributed Tracing and Chaos Engineering Control Bar."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone

import requests
import streamlit as st

# Configure logging
LOG_DIR = os.getenv("LOG_DIR", "./logs")
os.makedirs(LOG_DIR, exist_ok=True)
FRONTEND_LOG_FILE = os.path.join(LOG_DIR, "target_frontend.log")

BACKEND_URL = os.getenv("BACKEND_URL", "http://target-backend:8000")
# Local fallback if running outside docker
if not os.getenv("BACKEND_URL"):
    try:
        r = requests.get("http://localhost:8000/health", timeout=0.8)
        if r.status_code == 200:
            BACKEND_URL = "http://localhost:8000"
    except Exception:
        pass


def log_frontend(level: str, msg: str, trace_id: str, **extra):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level.upper(),
        "service": "target-frontend",
        "trace_id": trace_id,
        "msg": msg,
        **extra,
    }
    line = json.dumps(entry)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
    try:
        with open(FRONTEND_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


st.set_page_config(
    page_title="SRE E-Commerce Storefront",
    page_icon="🛒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for modern enterprise SRE look
st.markdown(
    """
    <style>
    .main-header { font-size: 2.2rem; font-weight: 700; color: #1E293B; margin-bottom: 0.2rem; }
    .sub-header { color: #64748B; margin-bottom: 1.5rem; font-size: 1rem; }
    .chaos-card { background-color: #FEF2F2; border: 1px solid #FCA5A5; border-radius: 8px; padding: 16px; margin-top: 20px; }
    .product-card { border: 1px solid #E2E8F0; border-radius: 8px; padding: 14px; margin-bottom: 12px; background: #FFFFFF; }
    .status-healthy { color: #16A34A; font-weight: 600; }
    .status-degraded { color: #DC2626; font-weight: 600; }
    </style>
    """,
    unsafe_allow_html=True,
)


def get_backend_health():
    trace_id = f"trace-health-{uuid.uuid4().hex[:8]}"
    try:
        resp = requests.get(f"{BACKEND_URL}/health", headers={"X-Request-ID": trace_id}, timeout=1.5)
        if resp.status_code == 200:
            return resp.json(), trace_id
        return {"status": "unhealthy", "code": resp.status_code}, trace_id
    except Exception as exc:
        log_frontend("WARN", f"Backend unreachable: {exc}", trace_id=trace_id)
        return {"status": "unreachable", "error": str(exc)}, trace_id


def fetch_products():
    trace_id = f"trace-prod-{uuid.uuid4().hex[:8]}"
    try:
        t0 = time.perf_counter()
        resp = requests.get(f"{BACKEND_URL}/products", headers={"X-Request-ID": trace_id}, timeout=3.5)
        duration_ms = round((time.perf_counter() - t0) * 1000, 2)
        if resp.status_code == 200:
            log_frontend("INFO", f"Fetched products successfully ({duration_ms}ms)", trace_id=trace_id)
            return resp.json().get("products", []), None, trace_id
        else:
            err_msg = resp.text
            log_frontend("ERROR", f"Failed fetching products HTTP {resp.status_code}: {err_msg}", trace_id=trace_id)
            return None, f"HTTP {resp.status_code}: {err_msg}", trace_id
    except Exception as e:
        log_frontend("ERROR", f"Exception connecting to /products: {e}", trace_id=trace_id)
        return None, str(e), trace_id


def place_order(product_id: int, quantity: int):
    trace_id = f"trace-order-{uuid.uuid4().hex[:8]}"
    try:
        t0 = time.perf_counter()
        resp = requests.post(
            f"{BACKEND_URL}/orders",
            json={"product_id": product_id, "quantity": quantity},
            headers={"X-Request-ID": trace_id},
            timeout=6.0,
        )
        duration_ms = round((time.perf_counter() - t0) * 1000, 2)
        if resp.status_code == 200:
            data = resp.json()
            log_frontend("INFO", f"Order placed successfully Order #{data.get('order_id')} ({duration_ms}ms)", trace_id=trace_id)
            return data, None, trace_id
        else:
            err_msg = resp.text
            log_frontend("ERROR", f"Order placement failed HTTP {resp.status_code}: {err_msg}", trace_id=trace_id)
            return None, f"HTTP {resp.status_code}: {err_msg}", trace_id
    except Exception as e:
        log_frontend("ERROR", f"Network failure on /orders: {e}", trace_id=trace_id)
        return None, str(e), trace_id


# App UI
st.markdown('<div class="main-header">🛒 CloudReliability Storefront</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Multi-Tier Microservice Target Application with Distributed Trace Propagation</div>', unsafe_allow_html=True)

# Top Status Bar
health, h_trace = get_backend_health()
status_str = health.get("status", "unknown")
chaos_mode = health.get("chaos_mode", "UNKNOWN")

col_s1, col_s2, col_s3, col_s4 = st.columns(4)
with col_s1:
    st.metric("Backend URL", BACKEND_URL)
with col_s2:
    st.metric("Service Health", status_str.upper())
with col_s3:
    st.metric("Active Chaos State", chaos_mode)
with col_s4:
    if st.button("🔄 Refresh Store"):
        st.rerun()

st.divider()

# Sidebar: Traffic Generation
with st.sidebar:
    st.subheader("⚙️ Storefront Simulator")
    st.write("Generate real customer load across the microservices stack:")
    auto_traffic = st.toggle("🤖 Enable Auto-Traffic Simulation", value=False)
    traffic_rate = st.slider("Requests per batch", min_value=1, max_value=10, value=3)

    if auto_traffic:
        st.caption("Firing synthetic background traffic...")
        # Auto-place random order
        o_res, o_err, o_tr = place_order(1, 1)
        if o_res:
            st.success(f"Auto-traffic: Order #{o_res.get('order_id')} OK ({o_tr})")
        else:
            st.error(f"Auto-traffic failed: {o_err} ({o_tr})")
        time.sleep(1.0)
        st.rerun()

# Products Grid
st.subheader("📦 Available Products Catalog")
products, err, p_trace = fetch_products()

if err:
    st.error(f"🚨 **Failed to Load Product Catalog** [Trace ID: `{p_trace}`]")
    st.code(err, language="json")
    st.warning("Notice: This failure is propagating distributed trace headers directly from Redis / Backend.")
elif products:
    cols = st.columns(3)
    for idx, prod in enumerate(products):
        with cols[idx % 3]:
            st.markdown(
                f"""
                <div class="product-card">
                    <h4>{prod['name']}</h4>
                    <p style="color:#64748B; font-size:0.85rem; height:40px;">{prod['description']}</p>
                    <p style="font-weight:700; color:#0F172A; font-size:1.1rem;">${prod['price']:.2f}</p>
                    <p style="font-size:0.8rem; color:#059669;">Stock: {prod['inventory']} units available</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            col_b1, col_b2 = st.columns([1, 2])
            with col_b1:
                qty = st.number_input("Qty", min_value=1, max_value=10, value=1, key=f"qty_{prod['id']}")
            with col_b2:
                if st.button("🛒 Buy Now", key=f"buy_{prod['id']}", use_container_width=True):
                    with st.spinner("Processing transaction..."):
                        res, order_err, o_trace = place_order(prod["id"], qty)
                        if res:
                            st.success(f"✅ Order confirmed! ID: #{res['order_id']} | Total: ${res['total_price']} [Trace: `{o_trace}`]")
                        else:
                            st.error(f"❌ Transaction Rejected [Trace: `{o_trace}`]")
                            st.code(order_err, language="text")

# Bottom: Chaos Engineering Control Bar
st.markdown("---")
st.markdown("### 🔥 SRE Chaos Engineering Control Bar")
st.caption("Inject production-grade failures to evaluate SentinelRCA's autonomous detection, RCA, and self-healing:")

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.error("**Scenario 1: DB Pool Leak**")
    st.caption("Saturates SQLAlchemy connection pool, triggering QueuePool timeouts on `/orders`.")
    if st.button("💥 Exhaust DB Pool", use_container_width=True):
        try:
            r = requests.post(f"{BACKEND_URL}/chaos/db-pool-exhaust", timeout=3.0)
            log_frontend("WARN", "Chaos injected: DB Pool Exhaustion", trace_id="chaos-control")
            # Immediately trigger failure requests so SRE Agent receives instant signal
            for _ in range(3):
                try:
                    requests.post(f"{BACKEND_URL}/orders", json={"product_id": 1, "quantity": 1}, timeout=3.5)
                except Exception:
                    pass
            st.toast("Injected DB Pool Exhaustion! Failure signal emitted to SRE Agent.", icon="💥")
            time.sleep(0.5)
            st.rerun()
        except Exception as e:
            st.error(f"Failed: {e}")

with c2:
    st.error("**Scenario 2: Redis Corruption**")
    st.caption("Injects malformed non-JSON bytes into Redis cache, breaking `/products` reads.")
    if st.button("💥 Corrupt Redis Cache", use_container_width=True):
        try:
            r = requests.post(f"{BACKEND_URL}/chaos/redis-corrupt", timeout=3.0)
            log_frontend("WARN", "Chaos injected: Redis Corruption", trace_id="chaos-control")
            # Immediately trigger failure requests so SRE Agent receives instant signal
            for _ in range(3):
                try:
                    requests.get(f"{BACKEND_URL}/products", timeout=2.0)
                except Exception:
                    pass
            st.toast("Injected Redis Cache Corruption! Failure signal emitted to SRE Agent.", icon="⚡")
            time.sleep(0.5)
            st.rerun()
        except Exception as e:
            st.error(f"Failed: {e}")

with c3:
    st.error("**Scenario 3: Bad Config & Latency**")
    st.caption("Applies impossible 1ms payment timeout + artificial delay, causing 504 cascades.")
    if st.button("💥 Push Bad Config", use_container_width=True):
        try:
            r = requests.post(f"{BACKEND_URL}/chaos/bad-config", timeout=3.0)
            log_frontend("WARN", "Chaos injected: Bad Config", trace_id="chaos-control")
            # Immediately trigger failure requests so SRE Agent receives instant signal
            for _ in range(3):
                try:
                    requests.post(f"{BACKEND_URL}/orders", json={"product_id": 1, "quantity": 1}, timeout=3.5)
                except Exception:
                    pass
            st.toast("Injected Bad Config & Latency! Failure signal emitted to SRE Agent.", icon="⏱️")
            time.sleep(0.5)
            st.rerun()
        except Exception as e:
            st.error(f"Failed: {e}")

with c4:
    st.success("**Self-Healing / Reset Baseline**")
    st.caption("Restore all configurations, dispose pools, flush Redis, and reset baseline.")
    if st.button("🌿 Reset to Healthy Baseline", use_container_width=True):
        try:
            r = requests.post(f"{BACKEND_URL}/admin/reset-all", timeout=3.0)
            st.toast("Baseline restored successfully!", icon="🌿")
            log_frontend("INFO", "Reset all chaos to healthy baseline", trace_id="chaos-control")
            time.sleep(0.5)
            st.rerun()
        except Exception as e:
            st.error(f"Failed: {e}")
