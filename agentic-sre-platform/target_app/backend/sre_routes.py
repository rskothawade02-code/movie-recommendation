"""SRE Mission Control REST API endpoints for React Frontend."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

# Ensure project and SRE roots in sys.path
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent.parent
SRE_ROOT = PROJECT_ROOT / "sre_platform"
for p in (str(PROJECT_ROOT), str(SRE_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from daemon.sre_daemon import sre_daemon
from onboarding.app_manager import app_manager
from onboarding.system_blueprint import generate_system_blueprint, load_system_blueprint
from telemetry.collector import collector
from tools.investigation_tools import execute_remediation, probe_endpoint

logger = logging.getLogger("sre_backend.routes")

router = APIRouter(prefix="/api/sre", tags=["SRE Mission Control"])


class ApprovalRequest(BaseModel):
    incident_id: str


class ToggleModeRequest(BaseModel):
    autonomous_mode: bool


@router.get("/status")
def get_sre_status():
    """Returns real-time status of 24/7 autonomous SRE daemon."""
    apps = app_manager.list_applications()
    active_app = apps[0].name if apps else "Target E-Commerce Microservices"
    return {
        "daemon_running": True,  # 24/7 background worker active
        "autonomous_mode": sre_daemon.autonomous_mode,
        "active_application": active_app,
        "total_incidents": len(sre_daemon.get_history()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/toggle-mode")
def toggle_autonomous_mode(req: ToggleModeRequest):
    sre_daemon.autonomous_mode = req.autonomous_mode
    return {"status": "updated", "autonomous_mode": sre_daemon.autonomous_mode}


@router.get("/latest-incident")
def get_latest_incident():
    """Returns the most recent or actively resolving incident."""
    inc = sre_daemon.get_latest_incident()
    return {"incident": inc}


@router.get("/history")
def get_incident_history():
    """Returns list of all historical resolved incidents."""
    history = sre_daemon.get_history()
    return {"history": list(reversed(history))}


@router.get("/blueprint")
def get_system_blueprint():
    """Returns the deep application system blueprint synthesized during onboarding."""
    bp = load_system_blueprint()
    if not bp:
        target_dir = Path("D:/RCA/agentic-sre-platform/target_app").resolve()
        bp = generate_system_blueprint(target_dir)
    return bp.model_dump()


@router.get("/telemetry")
def get_telemetry_snapshot():
    """Returns live telemetry stream, 15s sliding window error count, and trace IDs."""
    err_count, trace_ids, endpoints = collector.get_window_error_count(seconds=15)
    recent_logs = collector.get_recent_logs(limit=25)
    recent_metrics = collector.get_recent_metrics(limit=1)
    metric = recent_metrics[0] if recent_metrics else {}

    return {
        "error_count_15s": err_count,
        "sample_trace_ids": trace_ids[:6],
        "failing_endpoints": endpoints,
        "recent_logs": recent_logs,
        "http_5xx_rate": metric.get("http_5xx_rate", 0.0),
        "memory_mb": metric.get("memory_mb", 42.5),
    }


@router.post("/chaos/{scenario}")
def trigger_chaos_with_immediate_signal(scenario: str):
    """
    Injects a chaos failure AND immediately emits synthetic requests in background so
    the SRE agent receives an immediate failure signal (< 50ms) to start diagnosing.
    """
    import threading
    import requests
    from chaos import (
        inject_bad_config,
        inject_db_pool_exhaustion,
        inject_memory_pressure,
        inject_payment_outage,
        inject_redis_corruption,
    )

    backend_url = "http://127.0.0.1:8000"

    if scenario == "db-pool-exhaust":
        res = inject_db_pool_exhaustion()
        def _burst():
            time.sleep(0.1)
            for _ in range(3):
                try:
                    requests.post(f"{backend_url}/orders", json={"product_id": 1, "quantity": 1}, timeout=1.0)
                except Exception:
                    pass
        threading.Thread(target=_burst, daemon=True).start()
        return {"status": "injected", "scenario": scenario, "detail": res}

    elif scenario == "redis-corrupt":
        res = inject_redis_corruption()
        def _burst():
            time.sleep(0.1)
            for _ in range(3):
                try:
                    requests.get(f"{backend_url}/products", timeout=1.0)
                except Exception:
                    pass
        threading.Thread(target=_burst, daemon=True).start()
        return {"status": "injected", "scenario": scenario, "detail": res}

    elif scenario == "bad-config":
        res = inject_bad_config()
        def _burst():
            time.sleep(0.1)
            for _ in range(3):
                try:
                    requests.post(f"{backend_url}/orders", json={"product_id": 1, "quantity": 1}, timeout=1.0)
                except Exception:
                    pass
        threading.Thread(target=_burst, daemon=True).start()
        return {"status": "injected", "scenario": scenario, "detail": res}

    elif scenario == "payment-outage":
        res = inject_payment_outage()
        def _burst():
            time.sleep(0.1)
            for _ in range(3):
                try:
                    requests.post(f"{backend_url}/orders", json={"product_id": 1, "quantity": 1}, timeout=1.0)
                except Exception:
                    pass
        threading.Thread(target=_burst, daemon=True).start()
        return {"status": "injected", "scenario": scenario, "detail": res}

    elif scenario == "memory-pressure":
        res = inject_memory_pressure()
        def _burst():
            time.sleep(0.1)
            for _ in range(3):
                try:
                    requests.post(f"{backend_url}/orders", json={"product_id": 1, "quantity": 1}, timeout=1.0)
                except Exception:
                    pass
        threading.Thread(target=_burst, daemon=True).start()
        return {"status": "injected", "scenario": scenario, "detail": res}

    else:
        raise HTTPException(status_code=400, detail=f"Unknown chaos scenario '{scenario}'")


@router.post("/reset-baseline")
def reset_all_to_baseline():
    """Restore all chaos injectors back to healthy operational baseline."""
    from chaos import reset_all_chaos
    res = reset_all_chaos()
    return {"status": "healthy_baseline_restored", "detail": res}


@router.post("/approve")
def approve_remediation_action(req: ApprovalRequest):
    """Human-in-the-Loop operator approval for pending remediation."""
    res = sre_daemon.approve_and_heal(req.incident_id)
    return res


@router.post("/reject")
def reject_remediation_action(req: ApprovalRequest):
    """Human-in-the-Loop operator rejection for pending remediation."""
    res = sre_daemon.reject_action(req.incident_id)
    return res
