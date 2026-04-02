from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from cybersentry.core.detection.engine import DetectionEngine
from cybersentry.core.defense.ip_reputation import IPReputationEngine, IPVerdict
from cybersentry.core.defense.flood_guard import FloodGuard
from cybersentry.core.defense.fingerprint import FingerprintEngine
from cybersentry.core.defense.tarpit import HoneypotManager
from cybersentry.core.score.engine import ScoreEngine
import uvicorn, uuid, time
from collections import deque

app = FastAPI(title="CyberSentry Hardened Demo")

detection  = DetectionEngine(block_on_severity=["critical", "high"])
ip_rep     = IPReputationEngine(block_tor=True, block_abusive=True, challenge_datacenters=False)
flood      = FloodGuard(http_flood_rpm=500, http_flood_burst=100, conn_rate_per_sec=100)
fp_engine  = FingerprintEngine()
honeypot   = HoneypotManager()
score_eng  = ScoreEngine()

attack_log = deque(maxlen=200)
stats = {"total_requests":0, "blocked":0, "clean":0, "attacks_detected":0}

SKIP = {"/stats", "/log", "/docs", "/openapi.json", "/health"}

@app.middleware("http")
async def cybersentry_all_layers(request: Request, call_next):
    path   = str(request.url.path)
    method = request.method
    ip     = request.client.host if request.client else "127.0.0.1"
    req_id = str(uuid.uuid4())[:8]
    headers = dict(request.headers)

    stats["total_requests"] += 1

    if path in SKIP:
        return await call_next(request)

    # Layer 1 — IP reputation
    ip_result = ip_rep.check(ip)
    if ip_result.verdict == IPVerdict.BLOCK:
        stats["blocked"] += 1
        _log(req_id, ip, method, path, "IP_REP", ip_result.reason, "high", "blocked")
        return JSONResponse(status_code=403, content={"error":"blocked","reason":ip_result.reason})

    # Layer 2 — Flood guard
    header_size = sum(len(k)+len(v) for k,v in headers.items())
    content_len = int(headers.get("content-length", 0) or 0)
    flood_ok, flood_reason = flood.check_request(ip, method, path, header_size, content_len)
    if not flood_ok:
        stats["blocked"] += 1
        _log(req_id, ip, method, path, "FLOOD", flood_reason, "high", "blocked")
        return JSONResponse(status_code=429, content={"error":"rate_limited","reason":flood_reason},
                           headers={"Retry-After":"60"})

    # Layer 3 — Bot fingerprinting
    fp = fp_engine.fingerprint(ip, method, path, headers)
    if fp.recommended_action == "block" and not fp.is_known_good_bot:
        stats["blocked"] += 1
        _log(req_id, ip, method, path, "BOT", f"bot_score:{fp.bot_score}", "high", "blocked")
        return JSONResponse(status_code=403, content={"error":"blocked","reason":"bot_detected"})

    # Layer 5 — Honeypot
    if honeypot.is_honeypot(path):
        stats["blocked"] += 1
        ip_rep.ban(ip, 86400)
        _log(req_id, ip, method, path, "HONEYPOT", f"path:{path}", "high", "banned")
        status, body = honeypot.get_fake_response(path)
        from starlette.responses import PlainTextResponse
        return PlainTextResponse(body, status_code=status)

    # Read body
    body_dict = None
    if method in ("POST","PUT","PATCH"):
        try:
            import json as _json
            body_bytes = await request.body()
            body_str = body_bytes.decode("utf-8", errors="replace")
            ct = headers.get("content-type","")
            if "application/json" in ct:
                body_dict = _json.loads(body_bytes) if body_bytes else {}
            elif "form" in ct:
                from urllib.parse import parse_qs
                body_dict = {k:v[0] for k,v in parse_qs(body_str).items()}
        except Exception:
            pass

    # Layer 4 — OWASP detection
    analysis = detection.analyze(
        request_id=req_id, path=path, method=method,
        params=dict(request.query_params),
        body=body_dict, headers=headers, source_ip=ip,
    )

    if analysis.is_attack:
        stats["attacks_detected"] += 1
        for d in analysis.detections:
            _log(req_id, ip, method, path, d.rule_id, d.rule_name, d.severity,
                 "blocked" if analysis.blocked else "detected")

    if analysis.blocked:
        stats["blocked"] += 1
        return JSONResponse(
            status_code=403,
            content={
                "error": "request_blocked",
                "request_id": req_id,
                "threat_level": analysis.threat_level,
                "rules_triggered": [{"id":d.rule_id,"name":d.rule_name,"severity":d.severity}
                                     for d in analysis.detections],
                "message": "This request was blocked by CyberSentry.",
            },
            headers={
                "X-Request-ID": req_id,
                "X-CyberSentry": "blocked",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            }
        )

    stats["clean"] += 1
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def _log(req_id, ip, method, path, rule, rule_name, severity, action):
    attack_log.appendleft({
        "id": req_id, "time": time.strftime("%H:%M:%S"),
        "ip": ip, "method": method, "path": path,
        "params": f"{rule}:{rule_name}"[:80],
        "rule": rule, "rule_name": rule_name,
        "severity": severity, "action": action,
    })


@app.get("/search")
def search(q: str = ""):
    return {"query": q, "results": [{"id":1,"title":"Result 1"}]}

@app.get("/user")
def user(id: str = "1"):
    return {"id": id, "name": "Alice"}

@app.get("/file")
def read_file(name: str = "readme.txt"):
    return {"file": name}

@app.get("/fetch")
def fetch(url: str = "https://example.com"):
    return {"url": url}

@app.get("/ping")
def ping(host: str = "localhost"):
    return {"host": host, "result": "pong"}

@app.post("/login")
async def login(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    return {"status": "ok", "user": data.get("username","")}

@app.get("/stats")
def get_stats():
    attack_list = list(attack_log)
    counts = {
        "critical": sum(1 for a in attack_list if a.get("severity")=="critical"),
        "high":     sum(1 for a in attack_list if a.get("severity")=="high"),
        "medium":   sum(1 for a in attack_list if a.get("severity")=="medium"),
        "low":      sum(1 for a in attack_list if a.get("severity")=="low"),
    }
    score = score_eng.compute(**counts)
    return {**stats, "score":score.score, "grade":score.grade, "recent_attacks":attack_list[:20]}

@app.get("/log")
def get_log():
    return {"attacks": list(attack_log)}

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  CyberSentry — All 6 Defence Layers Active")
    print("="*55)
    print("  Layer 1  IP reputation + Tor")
    print("  Layer 2  DDoS + flood + slow loris")
    print("  Layer 3  Bot fingerprinting")
    print("  Layer 4  32 OWASP attack rules")
    print("  Layer 5  Honeypot traps")
    print("  Layer 6  Security headers")
    print("="*55)
    print("  http://localhost:8000")
    print("="*55 + "\n")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
