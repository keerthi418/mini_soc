from pathlib import Path
import csv, io, sqlite3, subprocess, re, socket, ipaddress, platform, json
from datetime import datetime, timezone
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from app.detector import analyze_logs, SAMPLE_LOGS

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
DB_PATH = ROOT / "sentinelx.db"
app = FastAPI(title="SentinelX", description="Consent-based local network inventory and SOC log investigation", version="1.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS devices(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, mac TEXT, hostname TEXT,
            discovered_at TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'local_arp_cache')""")
        c.execute("""CREATE TABLE IF NOT EXISTS access_requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_name TEXT NOT NULL, device_ip TEXT NOT NULL,
            purpose TEXT NOT NULL, requested_by TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            decision_reason TEXT, created_at TEXT NOT NULL, decided_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS audit_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL)""")

def audit(action, details):
    with db() as c:
        c.execute("INSERT INTO audit_log(action,details,created_at) VALUES(?,?,?)", (action, details, now()))

init_db()

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (STATIC / "index.html").read_text(encoding="utf-8")

@app.get("/api/health")
def health():
    return {"status":"online","service":"SentinelX","version":"1.1.0","database":"SQLite"}

@app.get("/api/sample")
def sample_analysis():
    return analyze_logs(SAMPLE_LOGS)

@app.post("/api/analyze")
async def upload_and_analyze(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a .csv log file.")
    raw = await file.read()
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File is too large. Maximum size is 5 MB.")
    try:
        rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not read CSV: {exc}")
    if not rows:
        raise HTTPException(status_code=400, detail="CSV contains no data rows.")
    result = analyze_logs(rows)
    audit("CSV_ANALYZED", f"{file.filename}: {len(rows)} rows")
    return result

@app.get("/api/sample.csv")
def sample_csv():
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["timestamp","username","source_ip","event","status"])
    writer.writeheader(); writer.writerows(SAMPLE_LOGS)
    return Response(content=output.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="sentinelx_sample_logs.csv"'})

def local_ipv4():
    # Determine the active interface address without sending traffic.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()

@app.post("/api/devices/scan")
def scan_devices():
    """Reads the OS ARP neighbor cache only. It does not inspect traffic or other devices' activity."""
    ip = local_ipv4()
    found = []
    if ip:
        try:
            output = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5, check=False).stdout
            for line in output.splitlines():
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})", line)
                if not m: continue
                addr, mac = m.group(1), m.group(2).replace("-", ":").lower()
                try:
                    parsed = ipaddress.ip_address(addr)
                    if parsed.is_private and addr != ip and not addr.endswith(".255"):
                        found.append({"ip":addr,"mac":mac,"hostname":"Unknown device"})
                except ValueError:
                    pass
        except (OSError, subprocess.TimeoutExpired):
            pass
    # Deduplicate and persist a timestamped inventory snapshot.
    dedup = {x["ip"]:x for x in found}
    with db() as c:
        for d in dedup.values():
            c.execute("INSERT INTO devices(ip,mac,hostname,discovered_at,source) VALUES(?,?,?,?,?)",
                      (d["ip"],d["mac"],d["hostname"],now(),"local_arp_cache"))
    audit("DEVICE_SCAN", f"ARP cache inventory: {len(dedup)} device(s); active interface {ip or 'unknown'}")
    return {"method":"OS ARP cache (passive)","local_ip":ip,"count":len(dedup),"devices":list(dedup.values()),
            "notice":"This is a best-effort snapshot, not guaranteed live Wi-Fi membership. Refresh the ARP cache by using your network normally. No device activity is monitored."}

@app.get("/api/devices")
def list_devices():
    with db() as c:
        rows = c.execute("SELECT * FROM devices ORDER BY id DESC LIMIT 100").fetchall()
    # Current scan snapshots can contain duplicates; keep latest record per IP.
    seen=set(); result=[]
    for r in rows:
        if r["ip"] not in seen:
            seen.add(r["ip"]); result.append(dict(r))
    return {"devices":result}

class RequestIn(BaseModel):
    device_name: str
    device_ip: str
    purpose: str
    requested_by: str = "Server laptop analyst"

@app.post("/api/requests")
def create_request(payload: RequestIn):
    for val in (payload.device_name, payload.device_ip, payload.purpose, payload.requested_by):
        if not val.strip(): raise HTTPException(status_code=400, detail="All request fields are required.")
    with db() as c:
        cur=c.execute("INSERT INTO access_requests(device_name,device_ip,purpose,requested_by,status,created_at) VALUES(?,?,?,?,?,?)",
          (payload.device_name.strip(),payload.device_ip.strip(),payload.purpose.strip(),payload.requested_by.strip(),"pending",now()))
        rid=cur.lastrowid
    audit("CONSENT_REQUEST_CREATED", f"Request #{rid} for {payload.device_name} ({payload.device_ip})")
    return {"id":rid,"status":"pending","message":"Request saved. The target laptop must open SentinelX and make its own decision; this server cannot force a prompt onto another laptop."}

class DecisionIn(BaseModel):
    decision: str
    reason: str

@app.get("/api/requests")
def list_requests():
    with db() as c:
        rows=c.execute("SELECT * FROM access_requests ORDER BY id DESC LIMIT 100").fetchall()
    return {"requests":[dict(r) for r in rows]}

@app.post("/api/requests/{request_id}/decision")
def decide_request(request_id: int, payload: DecisionIn):
    decision=payload.decision.lower().strip()
    if decision not in ("accepted","denied"): raise HTTPException(status_code=400, detail="Decision must be accepted or denied.")
    if not payload.reason.strip(): raise HTTPException(status_code=400, detail="Please explain why you accepted or denied this request.")
    with db() as c:
        row=c.execute("SELECT * FROM access_requests WHERE id=?",(request_id,)).fetchone()
        if not row: raise HTTPException(status_code=404, detail="Request not found.")
        if row["status"] != "pending": raise HTTPException(status_code=409, detail="This request already has a decision.")
        c.execute("UPDATE access_requests SET status=?,decision_reason=?,decided_at=? WHERE id=?",
                  (decision,payload.reason.strip(),now(),request_id))
    audit("CONSENT_DECISION", f"Request #{request_id}: {decision}; reason: {payload.reason.strip()}")
    return {"id":request_id,"status":decision,"reason":payload.reason.strip()}

@app.get("/api/audit")
def audit_events():
    with db() as c:
        rows=c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    return {"events":[dict(r) for r in rows]}

@app.get("/api/storage/status")
def storage_status():
    return {"database":"SQLite","database_file":"sentinelx.db","cloud_storage":"Not configured",
            "cloud_note":"Set up an approved cloud bucket and credentials before enabling uploads. Do not commit credentials or upload personal logs without authorization."}
