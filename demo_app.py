"""
CyberSentry — FastAPI Demo App
Shows real-time attack detection and blocking in action.

Run with:
    cd ~/Documents/cybersentry
    python3 demo_app.py

Then in another terminal:
    curl "http://localhost:8000/search?q=hello"              # clean - 200 OK
    curl "http://localhost:8000/search?q=' OR 1=1--"         # SQLi  - 403 BLOCKED
    curl "http://localhost:8000/search?q=<script>alert(1)"   # XSS   - 403 BLOCKED
    curl "http://localhost:8000/search?q=../../../etc/passwd" # Path  - 403 BLOCKED
    curl "http://localhost:8000/search?q=$(whoami)"           # CMDi  - 403 BLOCKED
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
import uuid
import time
from collections import deque
from datetime import datetime, timezone

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CyberSentry Demo App",
    description="A demo FastAPI app protected by CyberSentry",
    version="0.1.0",
)

# ── CyberSentry wired in ──────────────────────────────────────────────────────
from cybersentry.core.detection.engine import DetectionEngine
from cybersentry.core.detection.anomaly import AnomalyDetector
from cybersentry.core.score.engine import ScoreEngine

detection_engine = DetectionEngine(block_on_severity=["critical", "high"])
anomaly_detector = AnomalyDetector()
score_engine = ScoreEngine()

# ── In-memory attack log (last 100 events) ────────────────────────────────────
attack_log = deque(maxlen=100)
stats = {
    "total_requests": 0,
    "blocked": 0,
    "attacks_detected": 0,
    "clean": 0,
}


# ── Security middleware ───────────────────────────────────────────────────────
@app.middleware("http")
async def cybersentry_middleware(request: Request, call_next):
    start = time.monotonic()
    req_id = str(uuid.uuid4())[:8]
    client_ip = request.client.host if request.client else "unknown"

    stats["total_requests"] += 1

    # Skip the dashboard itself
    if request.url.path in ("/", "/dashboard", "/log", "/stats"):
        response = await call_next(request)
        return response

    # Read body for POST requests
    body_dict = None
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            import json
            body_bytes = await request.body()
            body_dict = json.loads(body_bytes) if body_bytes else {}
        except Exception:
            pass

    # Run detection
    analysis = detection_engine.analyze(
        request_id=req_id,
        path=str(request.url.path),
        method=request.method,
        params=dict(request.query_params),
        body=body_dict,
        headers=dict(request.headers),
        source_ip=client_ip,
    )

    elapsed_ms = (time.monotonic() - start) * 1000

    # Log the event
    if analysis.is_attack:
        stats["attacks_detected"] += 1
        for detection in analysis.detections:
            attack_log.appendleft({
                "id": req_id,
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "ip": client_ip,
                "method": request.method,
                "path": str(request.url.path),
                "params": str(dict(request.query_params))[:80],
                "rule": detection.rule_id,
                "rule_name": detection.rule_name,
                "severity": detection.severity,
                "matched_in": detection.matched_in,
                "action": "blocked" if analysis.blocked else "detected",
            })

    if analysis.blocked:
        stats["blocked"] += 1
        print(f"\n🚨 BLOCKED [{req_id}] {request.method} {request.url.path}")
        print(f"   IP: {client_ip}")
        print(f"   Params: {dict(request.query_params)}")
        for d in analysis.detections:
            print(f"   Rule: {d.rule_id} — {d.rule_name} [{d.severity.upper()}]")
        return JSONResponse(
            status_code=403,
            content={
                "error": "request_blocked",
                "request_id": req_id,
                "threat_level": analysis.threat_level,
                "rules_triggered": [
                    {"id": d.rule_id, "name": d.rule_name, "severity": d.severity}
                    for d in analysis.detections
                ],
                "message": "This request was blocked by CyberSentry.",
            },
            headers={
                "X-Request-ID": req_id,
                "X-CyberSentry": "blocked",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
        )

    stats["clean"] += 1
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"

    if analysis.is_attack:
        response.headers["X-CyberSentry-Threat"] = analysis.threat_level

    print(f"✅ OK      [{req_id}] {request.method} {request.url.path} — {elapsed_ms:.0f}ms")
    return response


# ── Demo API endpoints ────────────────────────────────────────────────────────
@app.get("/search")
def search(q: str = "", category: str = "all"):
    """Vulnerable search endpoint — try injecting into q parameter."""
    return {
        "query": q,
        "category": category,
        "results": [
            {"id": 1, "title": "Python Security Best Practices"},
            {"id": 2, "title": "OWASP Top 10 Guide"},
        ],
        "total": 2,
    }


@app.get("/user")
def get_user(id: str = "1"):
    """Vulnerable user lookup — try SQLi in id parameter."""
    users = {
        "1": {"id": 1, "name": "Alice", "role": "admin"},
        "2": {"id": 2, "name": "Bob", "role": "user"},
    }
    return users.get(id, {"error": "User not found"})


@app.post("/login")
async def login(request: Request):
    """Login endpoint — try SQLi/XSS in username/password."""
    try:
        data = await request.json()
    except Exception:
        data = {}
    username = data.get("username", "")
    return {"status": "ok", "user": username, "token": "demo-token-123"}


@app.get("/file")
def read_file(name: str = "readme.txt"):
    """File reader — try path traversal in name parameter."""
    return {"file": name, "content": "This is a demo file."}


@app.get("/ping")
def ping(host: str = "localhost"):
    """Ping endpoint — try command injection in host parameter."""
    return {"host": host, "result": "pong"}


@app.get("/fetch")
def fetch_url(url: str = "https://example.com"):
    """URL fetcher — try SSRF in url parameter."""
    return {"url": url, "status": "fetched"}


# ── Dashboard endpoints ───────────────────────────────────────────────────────
@app.get("/stats")
def get_stats():
    score_counts = {
        "critical": sum(1 for e in attack_log if e["severity"] == "critical"),
        "high": sum(1 for e in attack_log if e["severity"] == "high"),
        "medium": sum(1 for e in attack_log if e["severity"] == "medium"),
        "low": sum(1 for e in attack_log if e["severity"] == "low"),
    }
    score_result = score_engine.compute(**score_counts)
    return {
        **stats,
        "score": score_result.score,
        "grade": score_result.grade,
        "recent_attacks": list(attack_log)[:20],
    }


@app.get("/log")
def get_log():
    return {"attacks": list(attack_log)}


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    """Live attack monitoring dashboard."""
    return HTMLResponse(content=DASHBOARD_HTML)


# ── Dashboard HTML ────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberSentry Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0e1a; color: #e2e8f0; min-height: 100vh; }
.header { background: #0f1629; border-bottom: 1px solid #1e293b; padding: 16px 32px; display: flex; align-items: center; gap: 16px; }
.logo { font-size: 20px; font-weight: 700; color: #38bdf8; letter-spacing: -0.5px; }
.logo span { color: #94a3b8; font-weight: 400; font-size: 14px; margin-left: 8px; }
.live-dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; animation: pulse 2s infinite; margin-left: auto; }
.live-label { font-size: 12px; color: #22c55e; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
.grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; padding: 24px 32px 0; }
.card { background: #0f1629; border: 1px solid #1e293b; border-radius: 12px; padding: 20px; }
.card-label { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
.card-value { font-size: 32px; font-weight: 700; }
.card-value.green { color: #22c55e; }
.card-value.red { color: #ef4444; }
.card-value.yellow { color: #f59e0b; }
.card-value.blue { color: #38bdf8; }
.score-bar { margin-top: 8px; height: 4px; background: #1e293b; border-radius: 2px; overflow: hidden; }
.score-fill { height: 100%; background: #22c55e; border-radius: 2px; transition: width 0.5s; }
.section { padding: 24px 32px; }
.section-title { font-size: 14px; font-weight: 600; color: #94a3b8; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.5px; }
.attack-feed { background: #0f1629; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; }
.feed-header { display: grid; grid-template-columns: 70px 80px 60px 120px 1fr 100px 80px; gap: 12px; padding: 12px 16px; background: #0a0e1a; font-size: 11px; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; }
.feed-row { display: grid; grid-template-columns: 70px 80px 60px 120px 1fr 100px 80px; gap: 12px; padding: 12px 16px; border-top: 1px solid #1e293b; font-size: 13px; animation: fadeIn 0.3s; }
@keyframes fadeIn { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:translateY(0)} }
.feed-row:hover { background: #1e293b33; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.badge.critical { background: #7f1d1d; color: #fca5a5; }
.badge.high { background: #7c2d12; color: #fdba74; }
.badge.medium { background: #713f12; color: #fde047; }
.badge.low { background: #1e3a5f; color: #93c5fd; }
.badge.blocked { background: #7f1d1d; color: #fca5a5; }
.badge.detected { background: #1e3a5f; color: #93c5fd; }
.empty { text-align: center; padding: 48px; color: #475569; }
.cmd-section { padding: 0 32px 24px; }
.cmd-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.cmd-card { background: #0f1629; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; }
.cmd-card h4 { font-size: 12px; color: #64748b; margin-bottom: 8px; text-transform: uppercase; }
.cmd { background: #020617; border: 1px solid #1e293b; border-radius: 6px; padding: 8px 12px; font-family: 'SF Mono', monospace; font-size: 12px; color: #38bdf8; margin-bottom: 6px; }
.cmd .comment { color: #475569; }
</style>
</head>
<body>
<div class="header">
  <div class="logo">CyberSentry <span>Live Attack Monitor</span></div>
  <div class="live-dot"></div>
  <div class="live-label">LIVE</div>
</div>

<div class="grid">
  <div class="card">
    <div class="card-label">Security Score</div>
    <div class="card-value green" id="score">100</div>
    <div class="score-bar"><div class="score-fill" id="score-bar" style="width:100%"></div></div>
  </div>
  <div class="card">
    <div class="card-label">Total Requests</div>
    <div class="card-value blue" id="total">0</div>
  </div>
  <div class="card">
    <div class="card-label">Attacks Blocked</div>
    <div class="card-value red" id="blocked">0</div>
  </div>
  <div class="card">
    <div class="card-label">Clean Requests</div>
    <div class="card-value green" id="clean">0</div>
  </div>
</div>

<div class="section">
  <div class="section-title">Live Attack Feed</div>
  <div class="attack-feed">
    <div class="feed-header">
      <span>Time</span><span>IP</span><span>Method</span><span>Rule</span><span>Parameters</span><span>Severity</span><span>Action</span>
    </div>
    <div id="feed"><div class="empty">No attacks yet — fire some test commands below</div></div>
  </div>
</div>

<div class="cmd-section">
  <div class="section-title">Test Commands — run these in your terminal</div>
  <div class="cmd-grid">
    <div class="cmd-card">
      <h4>Clean requests (200 OK)</h4>
      <div class="cmd">curl "http://localhost:8000/search?q=hello"</div>
      <div class="cmd">curl "http://localhost:8000/user?id=1"</div>
    </div>
    <div class="cmd-card">
      <h4>SQL injection (403 Blocked)</h4>
      <div class="cmd">curl "http://localhost:8000/search?q=' OR 1=1--"</div>
      <div class="cmd">curl "http://localhost:8000/user?id=1 UNION SELECT * FROM users--"</div>
    </div>
    <div class="cmd-card">
      <h4>XSS attack (403 Blocked)</h4>
      <div class="cmd">curl "http://localhost:8000/search?q=&lt;script&gt;alert(1)&lt;/script&gt;"</div>
      <div class="cmd">curl "http://localhost:8000/search?q=&lt;img onerror=alert(1)&gt;"</div>
    </div>
    <div class="cmd-card">
      <h4>Other attacks (403 Blocked)</h4>
      <div class="cmd">curl "http://localhost:8000/file?name=../../../etc/passwd"</div>
      <div class="cmd">curl "http://localhost:8000/fetch?url=http://169.254.169.254"</div>
    </div>
  </div>
</div>

<script>
const SEV_COLORS = {critical:'critical', high:'high', medium:'medium', low:'low'};

async function refresh() {
  try {
    const r = await fetch('/stats');
    const d = await r.json();
    document.getElementById('score').textContent = d.score?.toFixed(1) || '100';
    document.getElementById('score-bar').style.width = (d.score || 100) + '%';
    document.getElementById('total').textContent = d.total_requests || 0;
    document.getElementById('blocked').textContent = d.blocked || 0;
    document.getElementById('clean').textContent = d.clean || 0;

    const feed = document.getElementById('feed');
    if (d.recent_attacks && d.recent_attacks.length > 0) {
      feed.innerHTML = d.recent_attacks.map(a => `
        <div class="feed-row">
          <span style="color:#475569">${a.time}</span>
          <span style="color:#94a3b8">${a.ip}</span>
          <span style="color:#64748b">${a.method}</span>
          <span style="color:#e2e8f0;font-weight:500">${a.rule}</span>
          <span style="color:#64748b;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.params}</span>
          <span><span class="badge ${SEV_COLORS[a.severity]||'low'}">${a.severity?.toUpperCase()}</span></span>
          <span><span class="badge ${a.action}">${a.action?.toUpperCase()}</span></span>
        </div>`).join('');
    } else {
      feed.innerHTML = '<div class="empty">No attacks yet — fire some test commands below</div>';
    }
  } catch(e) {}
}

refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  CyberSentry Demo App")
    print("="*60)
    print("  App:       http://localhost:8000")
    print("  Dashboard: http://localhost:8000/dashboard")
    print("  API docs:  http://localhost:8000/docs")
    print("  Stats API: http://localhost:8000/stats")
    print("="*60)
    print("  Endpoints to attack:")
    print("  GET  /search?q=    ← SQLi, XSS")
    print("  GET  /user?id=     ← SQLi")
    print("  GET  /file?name=   ← Path Traversal")
    print("  GET  /ping?host=   ← CMDi")
    print("  GET  /fetch?url=   ← SSRF")
    print("  POST /login        ← SQLi, XSS")
    print("="*60 + "\n")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")