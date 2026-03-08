"""
api/server.py — FastAPI REST API for ATILLA.

Allows programmatic scan triggering and result retrieval.
Useful for CI/CD pipelines and integration with external tools.

Usage:
    python3 main.py --api --api-port 8080

Endpoints:
    POST /scan          — start a new scan
    GET  /scan/{id}     — get scan status
    GET  /results/{id}  — get full results
    GET  /health        — health check
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, List, Optional

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

if HAS_FASTAPI:
    from core.config  import ScanConfig
    from core.engine  import ScanEngine
    from core.models  import Vulnerability

    app = FastAPI(
        title       = "ATILLA XSS Testing API",
        description = "Professional XSS scanner — authorized testing only",
        version     = "3.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins  = ["*"],
        allow_methods  = ["*"],
        allow_headers  = ["*"],
    )

    # In-memory scan store (swap for Redis/DB in production)
    _scans: Dict[str, dict] = {}

    # ── Request / Response schemas ─────────────────────────────────────────

    class ScanRequest(BaseModel):
        url:           str
        payload_set:   str                  = "owasp"
        auth_cookie:   Optional[str]        = None
        crawl:         bool                 = False
        crawl_depth:   int                  = 2
        timeout:       int                  = 15
        concurrency:   int                  = 3
        smart_context: bool                 = True
        use_mutations: bool                 = True
        blind_xss:     bool                 = False
        oob_host:      Optional[str]        = None
        include_cvss:  bool                 = False

    class ScanStatus(BaseModel):
        scan_id:    str
        status:     str       # queued | running | complete | error
        started_at: str
        ended_at:   Optional[str]
        url:        str
        findings:   int

    # ── Background scan task ───────────────────────────────────────────────

    async def _run_scan(scan_id: str, req: ScanRequest):
        _scans[scan_id]["status"] = "running"
        try:
            cfg   = ScanConfig(
                url            = req.url,
                auth_cookie    = req.auth_cookie,
                payload_set    = req.payload_set,
                timeout        = req.timeout,
                concurrency    = req.concurrency,
                crawl          = req.crawl,
                crawl_depth    = req.crawl_depth,
                smart_context  = req.smart_context,
                use_mutations  = req.use_mutations,
                blind_xss      = req.blind_xss,
                oob_host       = req.oob_host,
                include_cvss   = req.include_cvss,
            )
            vulns = await ScanEngine(cfg).run()
            _scans[scan_id]["status"]   = "complete"
            _scans[scan_id]["findings"] = [v.to_dict() for v in vulns]
            _scans[scan_id]["count"]    = len(vulns)
        except Exception as e:
            _scans[scan_id]["status"] = "error"
            _scans[scan_id]["error"]  = str(e)
        finally:
            _scans[scan_id]["ended_at"] = datetime.now().isoformat()

    # ── Endpoints ──────────────────────────────────────────────────────────

    @app.get("/health")
    def health():
        return {"status": "ok", "tool": "ATILLA v3.0"}

    @app.post("/scan", response_model=ScanStatus)
    async def start_scan(req: ScanRequest, background: BackgroundTasks):
        if not req.url.startswith(("http://", "https://")):
            raise HTTPException(400, "URL must start with http:// or https://")

        scan_id = str(uuid.uuid4())[:8]
        _scans[scan_id] = {
            "status":     "queued",
            "started_at": datetime.now().isoformat(),
            "ended_at":   None,
            "url":        req.url,
            "findings":   [],
            "count":      0,
        }
        background.add_task(_run_scan, scan_id, req)
        return ScanStatus(
            scan_id    = scan_id,
            status     = "queued",
            started_at = _scans[scan_id]["started_at"],
            ended_at   = None,
            url        = req.url,
            findings   = 0,
        )

    @app.get("/scan/{scan_id}", response_model=ScanStatus)
    def get_status(scan_id: str):
        s = _scans.get(scan_id)
        if not s:
            raise HTTPException(404, f"Scan {scan_id} not found")
        return ScanStatus(
            scan_id    = scan_id,
            status     = s["status"],
            started_at = s["started_at"],
            ended_at   = s.get("ended_at"),
            url        = s["url"],
            findings   = s["count"],
        )

    @app.get("/results/{scan_id}")
    def get_results(scan_id: str):
        s = _scans.get(scan_id)
        if not s:
            raise HTTPException(404, f"Scan {scan_id} not found")
        if s["status"] not in ("complete", "error"):
            raise HTTPException(202, f"Scan still {s['status']}")
        return {
            "scan_id":  scan_id,
            "url":      s["url"],
            "status":   s["status"],
            "count":    s["count"],
            "findings": s["findings"],
        }

    @app.get("/scans")
    def list_scans():
        return [
            {"scan_id": sid, "url": s["url"],
             "status": s["status"], "count": s["count"]}
            for sid, s in _scans.items()
        ]

    def start_server(port: int = 8080):
        try:
            import uvicorn
            print(f"[API] Starting ATILLA API on http://0.0.0.0:{port}")
            print(f"[API] Docs at http://localhost:{port}/docs")
            uvicorn.run(app, host="0.0.0.0", port=port)
        except ImportError:
            print("[API] Install uvicorn: pip install uvicorn fastapi")

else:
    def start_server(port: int = 8080):
        print("[API] Install FastAPI: pip install fastapi uvicorn")
