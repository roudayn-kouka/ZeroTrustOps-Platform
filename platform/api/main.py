"""
ZeroTrustOps Platform — Backend API
FastAPI application that:
  - Receives GitHub webhooks
  - Triggers SecTL scans
  - Stores results in PostgreSQL
  - Serves REST API for dashboard
"""

import asyncio
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import shutil
from datetime import datetime
from typing import Optional, List
from urllib.parse import urlsplit

import databases
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator

# ─── Config ───────────────────────────────────────────────────────────────────

DATABASE_URL = os.getenv("DATABASE_URL", "")
SECTL_PATH   = os.getenv("SECTL_PATH", "/usr/local/bin/sectl")
WORKSPACE    = os.getenv("WORKSPACE", "/workspace")
PLATFORM_API_KEY = os.getenv("PLATFORM_API_KEY", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "API_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,"
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

# ─── Database — asyncpg only, no psycopg2 ────────────────────────────────────

DB_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
database = databases.Database(DB_URL)

# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ZeroTrustOps Platform API",
    description="Security enforcement platform — scan before deploy",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["Content-Type", "X-API-Key"],
)

@app.middleware("http")
async def require_api_key(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        provided_key = request.headers.get("x-api-key", "")
        if not PLATFORM_API_KEY or not hmac.compare_digest(provided_key, PLATFORM_API_KEY):
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})
    return await call_next(request)

# ─── Startup / Shutdown ───────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL must be configured")
    if len(PLATFORM_API_KEY) < 32:
        raise RuntimeError("PLATFORM_API_KEY must contain at least 32 characters")
    if len(GITHUB_WEBHOOK_SECRET) < 32:
        raise RuntimeError("GITHUB_WEBHOOK_SECRET must contain at least 32 characters")
    await database.connect()
    os.makedirs(WORKSPACE, exist_ok=True)
    print("✅ Database connected")
    print(f"✅ SecTL: {SECTL_PATH}")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ─── Models ───────────────────────────────────────────────────────────────────

class RepoAdd(BaseModel):
    full_name: str = Field(min_length=3, max_length=200)
    clone_url: str = Field(min_length=1, max_length=500)
    branch: str = Field(default="main", min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_github_repository(self):
        validate_github_repo(self.full_name, self.clone_url)
        return self

    @field_validator("branch")
    @classmethod
    def validate_branch_name(cls, branch: str) -> str:
        return validate_branch(branch)

class TriggerScan(BaseModel):
    repo_full_name: str = Field(min_length=3, max_length=200)
    commit_sha: str = Field(default="manual", max_length=64)
    branch: Optional[str] = Field(default=None, min_length=1, max_length=100)
    triggered_by: str = Field(default="manual", max_length=255)
    commit_message: str = Field(default="Manual trigger", max_length=2000)

    @field_validator("branch")
    @classmethod
    def validate_branch_name(cls, branch: Optional[str]) -> Optional[str]:
        return validate_branch(branch) if branch is not None else None


def validate_branch(branch: str) -> str:
    segments = branch.split("/")
    if (
        not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", branch)
        or branch.startswith("/")
        or branch.endswith(("/", "."))
        or ".." in branch
        or "//" in branch
        or "@{" in branch
        or any(segment.startswith(".") or segment.endswith(".lock") for segment in segments)
    ):
        raise ValueError("Branch name is invalid")
    return branch


def validate_github_repo(full_name: str, clone_url: str) -> None:
    if not isinstance(full_name, str) or not re.fullmatch(
        r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", full_name
    ):
        raise ValueError("Repository must use the GitHub owner/repository format")

    if not isinstance(clone_url, str):
        raise ValueError("Clone URL must be a string")
    try:
        parsed = urlsplit(clone_url)
    except ValueError as exc:
        raise ValueError("Clone URL is invalid") from exc
    expected_paths = {f"/{full_name}", f"/{full_name}.git"}
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "github.com"
        or parsed.path not in expected_paths
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Clone URL must be the HTTPS URL for the specified GitHub repository")


def verify_github_signature(payload: bytes, signature: Optional[str]) -> bool:
    if not signature or not GITHUB_WEBHOOK_SECRET:
        return False
    expected = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)

# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "sectl": os.path.exists(SECTL_PATH),
        "version": "1.0.0"
    }

# ─── Repositories ─────────────────────────────────────────────────────────────

@app.get("/api/repos")
async def list_repos():
    """List all connected repositories."""
    rows = await database.fetch_all("""
        SELECT r.*, 
               COUNT(s.id) as total_scans,
               MAX(s.started_at) as last_scan,
               (SELECT gate_decision FROM scans 
                WHERE repo_id = r.id 
                ORDER BY started_at DESC LIMIT 1) as last_gate
        FROM repositories r
        LEFT JOIN scans s ON s.repo_id = r.id
        GROUP BY r.id
        ORDER BY r.created_at DESC
    """)
    return [dict(r) for r in rows]

@app.post("/api/repos")
async def add_repo(data: RepoAdd):
    """Add a new repository to scan."""
    # Check if already exists
    existing = await database.fetch_one(
        "SELECT id FROM repositories WHERE full_name = :full_name",
        {"full_name": data.full_name}
    )
    if existing:
        raise HTTPException(status_code=400, detail="Repository already connected")

    repo_id = await database.execute("""
        INSERT INTO repositories (org_id, name, full_name, clone_url, branch)
        VALUES (1, :name, :full_name, :clone_url, :branch)
        RETURNING id
    """, {
        "name": data.full_name.split("/")[-1],
        "full_name": data.full_name,
        "clone_url": data.clone_url,
        "branch": data.branch
    })
    return {"id": repo_id, "message": "Repository connected", "full_name": data.full_name}

@app.delete("/api/repos/{repo_id}")
async def remove_repo(repo_id: int):
    await database.execute("DELETE FROM repositories WHERE id = :id", {"id": repo_id})
    return {"message": "Repository removed"}

# ─── Scans ────────────────────────────────────────────────────────────────────

@app.get("/api/scans")
async def list_scans(
    repo_id: Optional[int] = None,
    limit: int = Query(default=20, ge=1, le=100),
):
    """List recent scans."""
    where = "WHERE s.repo_id = :repo_id" if repo_id else ""
    params = {"repo_id": repo_id, "limit": limit} if repo_id else {"limit": limit}

    rows = await database.fetch_all(f"""
        SELECT s.*, r.full_name as repo_name,
               COUNT(f.id) as finding_count,
               COUNT(CASE WHEN f.severity = 'CRITICAL' THEN 1 END) as critical_count,
               COUNT(CASE WHEN f.severity = 'HIGH' THEN 1 END) as high_count
        FROM scans s
        JOIN repositories r ON r.id = s.repo_id
        LEFT JOIN findings f ON f.scan_id = s.id
        {where}
        GROUP BY s.id, r.full_name
        ORDER BY s.started_at DESC
        LIMIT :limit
    """, params)
    return [dict(r) for r in rows]

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    """Get scan details with all findings."""
    scan = await database.fetch_one("""
        SELECT s.*, r.full_name as repo_name
        FROM scans s
        JOIN repositories r ON r.id = s.repo_id
        WHERE s.id = :id
    """, {"id": scan_id})

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = await database.fetch_all(
        "SELECT * FROM findings WHERE scan_id = :id ORDER BY severity DESC",
        {"id": scan_id}
    )

    return {**dict(scan), "findings": [dict(f) for f in findings]}

@app.post("/api/scans/trigger")
async def trigger_scan(data: TriggerScan, background_tasks: BackgroundTasks):
    """Manually trigger a scan."""
    repo = await database.fetch_one(
        "SELECT * FROM repositories WHERE full_name = :full_name",
        {"full_name": data.repo_full_name}
    )
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not connected. Add it first.")

    scan_branch = data.branch or repo.get("branch") or "main"
    scan_id = await database.execute("""
        INSERT INTO scans (repo_id, commit_sha, branch, triggered_by, commit_message, status)
        VALUES (:repo_id, :commit_sha, :branch, :triggered_by, :commit_message, 'pending')
        RETURNING id
    """, {
        "repo_id": repo["id"],
        "commit_sha": data.commit_sha,
        "branch": scan_branch,
        "triggered_by": data.triggered_by,
        "commit_message": data.commit_message
    })

    scan_repo = dict(repo)
    scan_repo["branch"] = scan_branch
    background_tasks.add_task(run_scan, scan_id, scan_repo)
    return {"scan_id": scan_id, "status": "queued", "message": "Scan started"}

# ─── GitHub Webhook ───────────────────────────────────────────────────────────

@app.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks,
                          x_github_event: str = Header(None),
                          x_hub_signature_256: str = Header(None)):
    """Receive GitHub push webhook and trigger scan."""
    body = await request.body()
    if not verify_github_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature")

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be a JSON object")

    # Only handle push events
    if x_github_event != "push":
        return {"message": f"Event '{x_github_event}' ignored — only push events trigger scans"}

    # Extract info from webhook payload
    ref = payload.get("ref", "")
    if not isinstance(ref, str) or not ref.startswith("refs/heads/"):
        return {"message": "Tag push ignored"}
    branch = ref.removeprefix("refs/heads/")
    try:
        validate_branch(branch)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    commit_sha  = payload.get("after", "unknown")
    repository = payload.get("repository")
    if not isinstance(repository, dict):
        raise HTTPException(status_code=400, detail="Repository info missing from payload")
    clone_url = repository.get("clone_url", "")
    full_name = repository.get("full_name", "")
    pusher_data = payload.get("pusher")
    pusher = pusher_data.get("name", "unknown") if isinstance(pusher_data, dict) else "unknown"
    head_commit = payload.get("head_commit", {})
    commit_msg = head_commit.get("message", "") if isinstance(head_commit, dict) else ""

    if not full_name:
        raise HTTPException(status_code=400, detail="Repository info missing from payload")
    try:
        validate_github_repo(full_name, clone_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if isinstance(commit_sha, str) and commit_sha and set(commit_sha) == {"0"}:
        return {"message": "Branch deletion ignored"}
    if not isinstance(commit_sha, str):
        raise HTTPException(status_code=400, detail="Commit SHA is invalid")

    # Find or auto-register repo
    repo = await database.fetch_one(
        "SELECT * FROM repositories WHERE full_name = :full_name",
        {"full_name": full_name}
    )

    if not repo:
        # Auto-register repo on first webhook
        repo_id = await database.execute("""
            INSERT INTO repositories (org_id, name, full_name, clone_url, branch)
            VALUES (1, :name, :full_name, :clone_url, :branch)
            RETURNING id
        """, {
            "name": full_name.split("/")[-1],
            "full_name": full_name,
            "clone_url": clone_url,
            "branch": branch
        })
        repo = await database.fetch_one(
            "SELECT * FROM repositories WHERE id = :id", {"id": repo_id}
        )

    # Create scan record
    scan_id = await database.execute("""
        INSERT INTO scans (repo_id, commit_sha, branch, triggered_by, commit_message, status)
        VALUES (:repo_id, :commit_sha, :branch, :triggered_by, :commit_message, 'pending')
        RETURNING id
    """, {
        "repo_id": repo["id"],
        "commit_sha": commit_sha[:8] if commit_sha else "unknown",
        "branch": branch,
        "triggered_by": pusher,
        "commit_message": commit_msg[:200] if commit_msg else "",
        "status": "pending"
    })

    # Run scan in background
    scan_repo = dict(repo)
    scan_repo["branch"] = branch
    background_tasks.add_task(run_scan, scan_id, scan_repo)

    return {
        "scan_id": scan_id,
        "repo": full_name,
        "branch": branch,
        "commit": commit_sha[:8] if commit_sha else "unknown",
        "pusher": pusher,
        "status": "scan_queued"
    }

# ─── Dashboard Stats ──────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    """Dashboard overview statistics."""
    stats = await database.fetch_one("""
        SELECT
            (SELECT COUNT(*) FROM repositories WHERE enabled = true) as total_repos,
            (SELECT COUNT(*) FROM scans) as total_scans,
            (SELECT COUNT(*) FROM scans WHERE gate_decision = 'PASS') as passed_scans,
            (SELECT COUNT(*) FROM scans WHERE gate_decision = 'FAIL') as failed_scans,
            (SELECT COUNT(*) FROM findings WHERE severity = 'CRITICAL') as total_critical,
            (SELECT COUNT(*) FROM findings WHERE severity = 'HIGH') as total_high,
            (SELECT COUNT(*) FROM scans WHERE status = 'running') as running_scans
    """)
    return dict(stats)

# ─── Core Scan Engine ─────────────────────────────────────────────────────────

async def run_scan(scan_id: int, repo: dict):
    """
    Main scan function — runs in background:
    1. Clone repo
    2. Run SecTL scan
    3. Store findings in DB
    4. Update scan status
    """
    started = datetime.now()
    work_dir = os.path.join(WORKSPACE, f"scan_{scan_id}")

    try:
        # Mark as running
        await database.execute(
            "UPDATE scans SET status = 'running' WHERE id = :id",
            {"id": scan_id}
        )

        # Step 1: Clone repository
        clone_url = repo["clone_url"]
        branch = repo.get("branch", "main")

        print(f"[Scan {scan_id}] Cloning {clone_url}...")
        validate_github_repo(repo["full_name"], clone_url)
        result = await asyncio.to_thread(
            subprocess.run,
            ["git", "clone", "--depth=1", f"--branch={branch}", clone_url, work_dir],
            capture_output=True, text=True, timeout=120,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed: {result.stderr[-2000:]}")

        # Step 2: Run SecTL K8s scan
        k8s_findings = []
        manifests_dir = None
        for candidate in ["manifests", "k8s", "kubernetes", "deploy", "."]:
            candidate_path = os.path.join(work_dir, candidate)
            if os.path.exists(candidate_path) and any(
                file.endswith((".yaml", ".yml")) for file in _walk_files(candidate_path)
            ):
                manifests_dir = candidate_path
                break

        if manifests_dir:
            print(f"[Scan {scan_id}] Running SecTL K8s scan on {manifests_dir}...")
            k8s_findings = await run_sectl(scan_id, manifests_dir, "k8s")

        # Step 3: Run SecTL Terraform scan
        tf_findings = []
        for candidate in ["infra", "terraform", "tf", "infrastructure"]:
            tf_path = os.path.join(work_dir, candidate)
            if os.path.exists(tf_path) and any(f.endswith(".tf") for f in _walk_files(tf_path)):
                print(f"[Scan {scan_id}] Running SecTL Terraform scan on {tf_path}...")
                tf_findings = await run_sectl(scan_id, tf_path, "terraform")
                break

        # Also check root for .tf files
        if not tf_findings and any(f.endswith(".tf") for f in os.listdir(work_dir)):
            tf_findings = await run_sectl(scan_id, work_dir, "terraform")

        # Step 4: Run Gitleaks secrets scan
        secrets_findings = await run_gitleaks(scan_id, work_dir)

        # Step 5: Collect all findings
        all_findings = k8s_findings + tf_findings + secrets_findings

        # Step 6: Store findings in DB
        for finding in all_findings:
            await database.execute("""
                INSERT INTO findings
                    (scan_id, tool, rule_id, severity, category, title, description, file_path, remediation)
                VALUES
                    (:scan_id, :tool, :rule_id, :severity, :category, :title, :description, :file_path, :remediation)
            """, {
                "scan_id": scan_id,
                "tool": finding.get("tool", "sectl"),
                "rule_id": finding.get("rule_id", ""),
                "severity": finding.get("severity", "INFO"),
                "category": finding.get("category", ""),
                "title": finding.get("title", "")[:500],
                "description": finding.get("description", "")[:1000],
                "file_path": finding.get("file", "")[:500],
                "remediation": finding.get("remediation", "")[:1000]
            })

        # Step 7: Make PASS/FAIL decision
        critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high     = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        gate     = "FAIL" if (critical > 0 or high > 0) else "PASS"

        duration = int((datetime.now() - started).total_seconds() * 1000)

        # Step 8: Update scan record
        await database.execute("""
            UPDATE scans SET
                status = :status,
                gate_decision = :gate,
                finished_at = NOW(),
                duration_ms = :duration
            WHERE id = :id
        """, {
            "status": "fail" if gate == "FAIL" else "pass",
            "gate": gate,
            "duration": duration,
            "id": scan_id
        })

        print(f"[Scan {scan_id}] ✅ Complete — Gate: {gate} | Findings: {len(all_findings)} | Duration: {duration}ms")

    except Exception as e:
        print(f"[Scan {scan_id}] ❌ Error: {e}")
        await database.execute("""
            UPDATE scans SET status = 'error', finished_at = NOW()
            WHERE id = :id
        """, {"id": scan_id})

    finally:
        # Cleanup cloned repo
        if os.path.exists(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)


async def run_sectl(scan_id: int, path: str, scan_type: str) -> list:
    """Run SecTL and return findings list."""
    result = await asyncio.to_thread(
        subprocess.run,
        [SECTL_PATH, "scan", path,
         "--type", scan_type,
         "--severity", "low",
         "--output", "json",
         "--quiet"],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"SecTL {scan_type} scan failed: {result.stderr[-2000:]}")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"SecTL {scan_type} returned invalid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise RuntimeError(f"SecTL {scan_type} returned an invalid scan result")

    findings = data["findings"]
    for finding in findings:
        finding["tool"] = "SecTL"
    return findings


async def run_gitleaks(scan_id: int, path: str) -> list:
    """Run Gitleaks secrets scan."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["docker", "run", "--rm",
             "--network=none",
             "-v", f"{path}:/repo:ro",
             "-v", f"{os.path.dirname(tmp_path)}:/report",
             "zricethezav/gitleaks:v8.30.1",
             "detect", "--source=/repo",
             "--report-format=json",
             f"--report-path=/report/{os.path.basename(tmp_path)}",
             "--exit-code=0"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Gitleaks scan failed: {result.stderr[-2000:]}")
        if not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
            raise RuntimeError("Gitleaks did not produce a report")

        with open(tmp_path, encoding="utf-8") as report_file:
            secrets_found = json.load(report_file)
        if not isinstance(secrets_found, list):
            raise RuntimeError("Gitleaks returned an invalid report")

        findings = []
        for finding in secrets_found:
            findings.append({
                "tool": "Gitleaks",
                "rule_id": finding.get("RuleID", "SECRET"),
                "severity": "CRITICAL",
                "category": "SECRETS",
                "title": finding.get("Description", "Secret detected"),
                "description": f"Secret found in {finding.get('File', '')}",
                "file": finding.get("File", "") + ":" + str(finding.get("StartLine", "")),
                "remediation": "Remove secret, rotate credentials, use environment variables."
            })
        return findings
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _walk_files(path: str):
    """Walk directory and yield file names."""
    for root, dirs, files in os.walk(path):
        for f in files:
            yield f
