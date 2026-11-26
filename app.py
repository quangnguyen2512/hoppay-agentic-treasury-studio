"""HopPay Agentic Treasury Studio — Zero-Config FastAPI Server & REST API.

Run locally in 1 command:
    python app.py
or:
    uvicorn app:app --reload --port 8090
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from treasury_engine import (
     DEFAULT_TREASURY_WALLET,
    SUPPORTED_TOKENS,
    AgentPlanRequest,
    AgenticTreasuryStudio,
    TreasuryPolicyConfig,
    build_preset_requests,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
ASSETS_DIR = BASE_DIR / "assets"

app = FastAPI(
    title="HopPay Agentic Treasury Studio",
    version="1.0.0",
    description="Autonomous AI CFO Planner, Deterministic Policy Guard, Anomaly Circuit Breaker & Multi-Hop Solana USDC/USDG Router",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR.mkdir(parents=True, exist_ok=True)
ASSETS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

STUDIO = AgenticTreasuryStudio()


def _seed_initial_demo_state() -> None:
    """Pre-populate the studio with the clean USDG payroll plan so first page load shows rich data immediately."""
    if not STUDIO.plans:
        presets = build_preset_requests(STUDIO)
        STUDIO.create_plan(presets["clean_usdg_payroll"]["request"])


_seed_initial_demo_state()


class ApprovalPayload(BaseModel):
    approver: str = Field(default="@quangnguyen2512", max_length=64)
    note: str = Field(default="Verified contributor milestones & Token-2022 USDG mint parameters.", max_length=280)


class SimulatePayload(BaseModel):
    allow_network: bool = Field(default=True)


class PresetOverridePayload(BaseModel):
    policy: TreasuryPolicyConfig | None = None


@app.get("/", include_in_schema=False)
def serve_dashboard() -> FileResponse:
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="static/index.html not found")
    return FileResponse(str(index_file))


@app.get("/api/health")
def api_health() -> dict[str, Any]:
    integrity = STUDIO.verify_ledger_integrity()
    return {
        "status": "ok",
        "service": "hoppay-agentic-treasury-studio",
        "version": "1.0.0",
        "default_treasury_wallet": DEFAULT_TREASURY_WALLET,
        "supported_tokens": SUPPORTED_TOKENS,
        "plans_count": len(STUDIO.plans),
        "audit_chain": integrity,
    }


@app.get("/api/contributors")
def api_contributors() -> dict[str, Any]:
    items = [c.model_dump() for c in STUDIO.contributors.values()]
    return {"count": len(items), "contributors": items}


@app.get("/api/presets")
def api_presets() -> dict[str, Any]:
    presets = build_preset_requests(STUDIO)
    out = []
    for key, item in presets.items():
        out.append(
            {
                "id": key,
                "badge": item["badge"],
                "title": item["title"],
                "description": item["description"],
                "request": item["request"].model_dump(),
            }
        )
    return {"presets": out}


@app.post("/api/presets/{preset_id}/run")
def api_run_preset(preset_id: str, body: PresetOverridePayload | None = None) -> dict[str, Any]:
    presets = build_preset_requests(STUDIO)
    if preset_id not in presets:
        raise HTTPException(status_code=404, detail=f"Unknown preset '{preset_id}'")
    req: AgentPlanRequest = presets[preset_id]["request"].model_copy(deep=True)
    if body and body.policy is not None:
        req.policy = body.policy
    plan = STUDIO.create_plan(req)
    return plan


@app.post("/api/plans")
def api_create_plan(req: AgentPlanRequest) -> dict[str, Any]:
    try:
        return STUDIO.create_plan(req)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/plans")
def api_list_plans() -> dict[str, Any]:
    ordered = list(reversed(list(STUDIO.plans.values())))
    return {"count": len(ordered), "plans": ordered}


@app.get("/api/plans/{plan_id}")
def api_get_plan(plan_id: str) -> dict[str, Any]:
    if plan_id not in STUDIO.plans:
        raise HTTPException(status_code=404, detail=f"Plan '{plan_id}' not found")
    return STUDIO.plans[plan_id]


@app.post("/api/plans/{plan_id}/approve")
def api_approve_plan(plan_id: str, payload: ApprovalPayload) -> dict[str, Any]:
    try:
        return STUDIO.approve_plan(plan_id, approver=payload.approver, note=payload.note)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/plans/{plan_id}/simulate-devnet")
def api_simulate_devnet(plan_id: str, payload: SimulatePayload | None = None) -> dict[str, Any]:
    allow_net = True if payload is None else payload.allow_network
    try:
        sim = STUDIO.simulate_devnet(plan_id, allow_network=allow_net)
        return {"plan_id": plan_id, "simulation": sim, "plan": STUDIO.plans[plan_id]}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/audit-ledger")
def api_audit_ledger() -> dict[str, Any]:
    return {
        "integrity": STUDIO.verify_ledger_integrity(),
        "entries": [e.model_dump() for e in reversed(STUDIO.ledger)],
    }


@app.get("/api/plans/{plan_id}/export")
def api_export_plan_pack(plan_id: str) -> JSONResponse:
    if plan_id not in STUDIO.plans:
        raise HTTPException(status_code=404, detail=f"Plan '{plan_id}' not found")
    pack = {
        "exported_by": "HopPay Agentic Treasury Studio v1.0.0",
        "ledger_integrity": STUDIO.verify_ledger_integrity(),
        "plan": STUDIO.plans[plan_id],
    }
    return JSONResponse(
        content=pack,
        headers={
            "Content-Disposition": f'attachment; filename="hoppay_audit_{plan_id}.json"'
        },
    )


if __name__ == "__main__":
    import os
    import uvicorn

    uvicorn.run(
        "app:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8790")),
        reload=False,
    )
