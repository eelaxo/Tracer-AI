"""
Tracer AI - minimal working prototype backend.

- No real blockchain calls: the "indexer" generates a plausible,
  DETERMINISTIC transaction graph from whatever wallet address is
  submitted (same input -> same graph, like a real lookup would be).
- Risk scoring is a small transparent weighted formula (documented
  in the pitch deck) instead of a trained model.
- Storage is a single JSON file (cases.json) - good enough for a
  hackathon demo, zero setup, but it resets on Render's free tier
  whenever the service restarts.
- Visitor activity (page views + submitted wallet addresses) is
  logged to a real Postgres database instead, so it survives
  restarts. See README for how to point this at a free Supabase/
  Neon database via the DATABASE_URL environment variable.

Security hardening applied (Phase 1):
  - Connection pooling via ThreadedConnectionPool (no per-request connects)
  - log_activity runs as a FastAPI BackgroundTask (non-blocking async)
  - Strict Pydantic input validation on wallet address (regex + length)
  - IP validation via ipaddress module (blocks X-Forwarded-For spoofing)
  - CORS middleware added
  - Chain whitelist enforced

Pages:
    /          scroll-driven story (demo.html) - how the system works
    /app       the working tool (app.html)     - enter or pull a report
    /visitors  password-protected activity log (owner only)

Run:
    pip install -r requirements.txt
    uvicorn app:app --reload
    open http://127.0.0.1:8000
"""
import hashlib
import html
import ipaddress
import json
import math
import os
import random
import re
import secrets
import string
import threading
import time
import uuid
from pathlib import Path

import psycopg2
import psycopg2.pool
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field, field_validator

APP_DIR = Path(__file__).parent
DB_FILE = APP_DIR / "cases.json"
_FILE_LOCK = threading.Lock()  # prevents race conditions on cases.json

app = FastAPI(title="Tracer AI (prototype)")

# ---------------------------------------------------------------- CORS
# Allows the frontend pages to call the API even when served from a
# different origin (e.g. a preview URL on Render or Vercel).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------- visitor log (Postgres)
# Separate from cases.json: this is the part that must survive a
# Render restart, so it lives in a real database, not a local file.
DATABASE_URL = os.environ.get("DATABASE_URL")  # set this in Render's Environment tab
VISITORS_PASSWORD = os.environ.get("VISITORS_PASSWORD")  # set this too, don't hardcode it

# ---- Connection pool (replaces bare psycopg2.connect on every request) ----
# minconn=1 keeps one warm connection alive; maxconn=8 stops us hitting
# the Supabase/Neon free-tier connection limit (typically 15-20).
_pool: psycopg2.pool.ThreadedConnectionPool | None = None
_pool_lock = threading.Lock()

def _get_pool() -> psycopg2.pool.ThreadedConnectionPool | None:
    global _pool
    if not DATABASE_URL:
        return None
    with _pool_lock:
        if _pool is None or _pool.closed:
            try:
                _pool = psycopg2.pool.ThreadedConnectionPool(
                    minconn=1, maxconn=8,
                    dsn=DATABASE_URL,
                    connect_timeout=3,
                )
            except Exception as e:
                print("DB pool init failed:", e)
                return None
    return _pool

def db_connect():
    """Get a connection from the pool (caller must return it via pool.putconn)."""
    pool = _get_pool()
    if pool is None:
        raise RuntimeError("No database pool available")
    return pool.getconn()

def db_putconn(conn) -> None:
    pool = _get_pool()
    if pool and conn:
        pool.putconn(conn)

# ---------------------------------------------------------------- safe IP extraction
def client_ip(request: Request) -> str:
    """
    Extract the real client IP.
    Validates the value from X-Forwarded-For so a spoofed header with
    arbitrary text (e.g. injection payloads) is silently discarded.
    """
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        candidate = fwd.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)   # raises ValueError if not a valid IP
            return candidate
        except ValueError:
            pass
    if request.client:
        return request.client.host
    return "unknown"

# ---------------------------------------------------------------- activity logging (non-blocking)
def log_activity(ip: str, path: str, wallet: str | None = None) -> None:
    """
    Best-effort background logging — a hiccup here must never block a response.
    Called via FastAPI BackgroundTasks so it runs AFTER the response is sent,
    keeping the async event loop free.
    """
    if not DATABASE_URL:
        return
    conn = None
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS activity ("
                "id SERIAL PRIMARY KEY, ts TIMESTAMPTZ DEFAULT now(), "
                "ip TEXT, path TEXT, wallet TEXT)"
            )
            cur.execute(
                "INSERT INTO activity (ip, path, wallet) VALUES (%s, %s, %s)",
                (ip, path, (wallet or None)[:200] if wallet else None),
            )
        conn.commit()
    except Exception as e:
        print("activity log failed:", e)
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
    finally:
        db_putconn(conn)

# ---------------------------------------------------------------- middleware
# NOTE: We no longer call log_activity here because that was a blocking
# psycopg2 call inside an async function — it would freeze the event loop.
# Page-view logging is now done per-route via BackgroundTasks instead.
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# ---------------------------------------------------------------- storage
def _file_db() -> dict:
    if not DB_FILE.exists():
        return {}
    try:
        return json.loads(DB_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}

def _file_db_write(db: dict) -> None:
    """Atomic-ish write using a lock to prevent concurrent corruption."""
    with _FILE_LOCK:
        tmp = DB_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(db, indent=2), encoding="utf-8")
        tmp.replace(DB_FILE)

def save_case(case: dict) -> None:
    if DATABASE_URL:
        conn = None
        try:
            conn = db_connect()
            with conn.cursor() as cur:
                cur.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, data JSONB)")
                cur.execute(
                    "INSERT INTO cases (id, data) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
                    (case["case_id"], json.dumps(case)),
                )
            conn.commit()
            return
        except Exception as e:
            print("save_case: DB unavailable, falling back to file ->", e)
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
        finally:
            db_putconn(conn)
    # file fallback
    with _FILE_LOCK:
        db = _file_db()
        db[case["case_id"]] = case
        _file_db_write(db)

def get_case_by_id(case_id: str) -> dict | None:
    if DATABASE_URL:
        conn = None
        try:
            conn = db_connect()
            with conn.cursor() as cur:
                cur.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, data JSONB)")
                cur.execute("SELECT data FROM cases WHERE id = %s", (case_id,))
                row = cur.fetchone()
                return row[0] if row else None
        except Exception as e:
            print("get_case_by_id: DB unavailable, falling back to file ->", e)
        finally:
            db_putconn(conn)
    return _file_db().get(case_id)

def list_recent_cases(limit: int = 20) -> list[dict]:
    """
    Returns lightweight summary rows only — NOT the full graph payload.
    This avoids pulling megabytes of node/edge data just to show 6 chips.
    """
    if DATABASE_URL:
        conn = None
        try:
            conn = db_connect()
            with conn.cursor() as cur:
                cur.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, data JSONB)")
                # Pull only the fields we need for the summary list
                cur.execute(
                    """
                    SELECT
                        data->>'case_id',
                        (data->>'created_at')::bigint,
                        data->'input'->>'wallet',
                        data->'vasp'->>'name',
                        (data->'vasp'->>'confidence')::float,
                        (data->'summary'->>'funds_reached_exchange')::float
                    FROM cases
                    ORDER BY (data->>'created_at')::bigint DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
                return [
                    {
                        "case_id": r[0], "created_at": r[1], "wallet": r[2],
                        "vasp": r[3], "confidence": r[4], "funds_reached_exchange": r[5],
                    }
                    for r in rows
                ]
        except Exception as e:
            print("list_recent_cases: DB unavailable, falling back to file ->", e)
        finally:
            db_putconn(conn)
    # file fallback
    cases = list(_file_db().values())
    cases.sort(key=lambda c: -c.get("created_at", 0))
    return [
        {
            "case_id": c["case_id"], "created_at": c["created_at"],
            "wallet": c["input"]["wallet"], "vasp": c["vasp"]["name"],
            "confidence": c["vasp"]["confidence"],
            "funds_reached_exchange": c["summary"]["funds_reached_exchange"],
        }
        for c in cases[:limit]
    ]

# ---------------------------------------------------------------- fake but plausible addresses
def fake_address(rng: random.Random, chain: str) -> str:
    if chain == "TRX":
        alphabet = string.ascii_letters + string.digits
        return "T" + "".join(rng.choice(alphabet) for _ in range(33))
    alphabet = "0123456789abcdef"
    return "0x" + "".join(rng.choice(alphabet) for _ in range(40))

def short(addr: str) -> str:
    return addr[:6] + "…" + addr[-4:]

VASP_POOL = ["ExampleX Exchange", "CoinHarbor", "NovaTrade", "ZenithSwap"]
CATEGORY_POOL = [
    "Investment scam", "Task-based fraud", "Sextortion",
    "Phishing", "Ransomware", "Romance scam",
]
ALLOWED_CHAINS = {"ETH", "TRX"}

# ---------------------------------------------------------------- risk model
# Same transparent weighted model used in the pitch: features in [0,1],
# fixed weights, logistic squash. Swap-in point for a trained model later.
WEIGHTS = {
    "inflow": 2.2, "speed": 1.6, "fanOut": 1.2, "mixer": 2.0,
    "bridge": 1.0, "fresh": 1.1, "split": 0.8, "service": -2.5,
}
BIAS = -2.2

def score(features: dict) -> tuple[float, list[dict]]:
    z = BIAS
    contribs = []
    for k, w in WEIGHTS.items():
        v = features.get(k, 0.0)
        c = w * v
        z += c
        if v > 0:
            contribs.append({"feature": k, "value": round(v, 2), "contribution": round(c, 2)})
    p = 1 / (1 + math.exp(-z))
    contribs.sort(key=lambda r: -abs(r["contribution"]))
    return p, contribs

TYPE_FEATURES = {
    "reported": lambda r: {"inflow": .9, "speed": .6, "fanOut": .5, "fresh": .8, "split": .3},
    "burner":   lambda r: {"speed": .8 + r.uniform(0, .15), "fanOut": .2, "fresh": .85, "split": .4},
    "mixer":    lambda r: {"mixer": 1.0, "fanOut": .8, "fresh": .2, "split": .7},
    "bridge":   lambda r: {"bridge": 1.0, "speed": .5, "split": .3},
    "deposit":  lambda r: {"speed": .95, "fresh": .6, "service": .9},
    "hotwallet":lambda r: {"speed": .3, "fanOut": .5, "service": .97},
}
TYPE_ROLE = {
    "reported": "Reported wallet (collection)", "burner": "Layering / burner wallet",
    "mixer": "Mixer", "bridge": "Cross-chain bridge",
    "deposit": "Exchange deposit address", "hotwallet": "Exchange hot wallet (VASP)",
    "victim": "Victim wallet", "fiat": "Fiat off-ramp",
}

# ---------------------------------------------------------------- graph generation
def build_case(wallet: str, chain: str, amount: float, category: str) -> dict:
    seed = hashlib.sha256(wallet.encode()).hexdigest()
    rng = random.Random(seed)

    nodes, edges = [], []
    nid = [0]
    def add_node(type_, addr, chain_):
        nid[0] += 1
        n = {"id": f"n{nid[0]}", "type": type_, "chain": chain_, "address": addr,
             "label": TYPE_ROLE[type_], "short": short(addr) if addr != "fiat" else "fiat"}
        if type_ in TYPE_FEATURES:
            feats = TYPE_FEATURES[type_](rng)
            p, contribs = score(feats)
            n["risk"] = round(p * 100)
            n["reasons"] = contribs            # every signal that fired
            n["top_reasons"] = contribs[:3]    # kept for older clients
        nodes.append(n)
        return n

    def add_edge(a, b, amt):
        edges.append({"from": a["id"], "to": b["id"], "amount": round(amt, 2)})

    # L0 victims -> L1 reported wallet
    reported = add_node("reported", wallet, chain)
    n_victims = rng.randint(1, 3)
    victim_amounts = [amount] + [round(amount * rng.uniform(.3, 1.4), 2) for _ in range(n_victims - 1)]
    for va in victim_amounts:
        v = add_node("victim", fake_address(rng, "ETH"), "ETH")
        add_edge(v, reported, va)
    total_in = sum(victim_amounts)

    # L2 burners, splitting the inflow
    n_burn = rng.randint(2, 3)
    splits = [rng.uniform(.6, 1.4) for _ in range(n_burn)]
    ssum = sum(splits)
    burners = []
    for s in splits:
        amt = total_in * (s / ssum) * rng.uniform(.9, .98)
        b = add_node("burner", fake_address(rng, chain), chain)
        add_edge(reported, b, amt)
        burners.append((b, amt))

    # L3 obfuscation (mixer / bridge / straight through) -> L4 deposit
    deposits = []
    bridge_target_chain = "TRX" if chain == "ETH" else "ETH"
    for b, amt in burners:
        roll = rng.random()
        if roll < .4:
            m = add_node("mixer", fake_address(rng, chain), chain)
            add_edge(b, m, amt)
            out_amt = amt * rng.uniform(.95, .99)
            d = add_node("deposit", fake_address(rng, chain), chain)
            add_edge(m, d, out_amt)
            deposits.append((d, out_amt))
        elif roll < .7:
            br = add_node("bridge", fake_address(rng, chain), chain)
            add_edge(b, br, amt)
            out_amt = amt * rng.uniform(.96, .995)
            d = add_node("deposit", fake_address(rng, bridge_target_chain), bridge_target_chain)
            add_edge(br, d, out_amt)
            deposits.append((d, out_amt))
        else:
            d = add_node("deposit", fake_address(rng, chain), chain)
            add_edge(b, d, amt)
            deposits.append((d, amt))

    # L5 hot wallet (VASP) <- all deposits ; L6 fiat off-ramp
    hot = add_node("hotwallet", fake_address(rng, chain), chain)
    total_reached = 0.0
    for d, amt in deposits:
        add_edge(d, hot, amt)
        total_reached += amt
    fiat = add_node("fiat", "fiat", "")
    add_edge(hot, fiat, total_reached)

    vasp_name = rng.choice(VASP_POOL)
    confidence = round(rng.uniform(84, 97), 1)

    dep_nodes = [d for d, _ in deposits]
    avg_dep_risk = round(sum(d["risk"] for d in dep_nodes) / len(dep_nodes))
    share = round(total_reached / total_in * 100)
    evidence = [
        f"{len(deposits)} separate paths end in deposit addresses that sweep into one hot wallet",
        f"{share}% of the reported funds reached this single cluster",
        f"Deposit and hot wallets look like a regulated service (avg laundering risk {avg_dep_risk}%)",
    ]

    case_id = "NCRP-" + uuid.uuid4().hex[:8].upper()
    case = {
        "case_id": case_id,
        "created_at": int(time.time()),
        "input": {"wallet": wallet, "chain": chain, "amount": amount, "category": category},
        "summary": {
            "wallets_found": len(nodes),
            "hops": 5,
            "chains": sorted({n["chain"] for n in nodes if n["chain"]}),
            "funds_reported": round(total_in, 2),
            "funds_reached_exchange": round(total_reached, 2),
        },
        "nodes": nodes,
        "edges": edges,
        "vasp": {"name": vasp_name, "confidence": confidence, "wallet": hot["short"], "evidence": evidence},
        "freeze_request": (
            f"DRAFT — for investigators only (simulated)\n\n"
            f"Authority: Sec. 94 BNSS 2023 / Sec. 91 CrPC | Sec. 106 BNSS / Sec. 102 CrPC\n\n"
            f"To: {vasp_name} Compliance & Legal Team*\n"
            f"From: [Investigating Officer Name]\n"
            f"Station / Cyber Cell: [Police Station / Cyber Crime Cell]\n"
            f"FIR / NCRP Ref: {case_id}\n\n"
            f"Subject: Request to Freeze Accounts & Preserve KYC Records\n\n"
            f"Reported wallet: {wallet}\n"
            f"Deposit wallets: " + ", ".join(d["short"] for d, _ in deposits) + f"\n"
            f"Hot wallet cluster: {hot['short']}\n"
            f"Funds reaching exchange: {round(total_reached, 2)} USDT\n"
            f"Attribution confidence: {confidence}%\n"
            f"Fraud category: {category}\n\n"
            f"You are hereby requested under the above provisions to:\n"
            f"  1. Immediately freeze all accounts linked to the above addresses.\n"
            f"  2. Preserve full KYC records, transaction logs, and IP/device data.\n"
            f"  3. Respond within 7 working days with account holder details.\n\n"
            f"* Fictional exchange name — for demo purposes only."
        ),
    }
    return case

# ---------------------------------------------------------------- simulated NCRP lookup
def simulated_ncrp_complaint(complaint_id: str) -> dict:
    rng = random.Random(hashlib.sha256(complaint_id.encode()).hexdigest())
    chain = rng.choice(["ETH", "TRX"])
    return {
        "complaint_id": complaint_id,
        "category": rng.choice(CATEGORY_POOL),
        "amount": rng.choice([4500, 8200, 12000, 18500, 25000, 31000]),
        "chain": chain,
        "wallet": fake_address(rng, chain),
        "filed_days_ago": rng.randint(0, 6),
    }

# ---------------------------------------------------------------- API input model with validation
# Wallet pattern: Ethereum (0x + 40 hex chars) OR TRON (T + 33 base58 chars)
_WALLET_RE = re.compile(r"^(0x[0-9a-fA-F]{40}|T[1-9A-HJ-NP-Za-km-z]{33})$")

class ReportIn(BaseModel):
    wallet: str = Field(..., min_length=26, max_length=66)
    chain: str = Field("ETH", max_length=8)
    amount: float = Field(5000, ge=1, le=1_000_000_000)
    category: str = Field("Investment scam", max_length=64)
    source: str = Field("manual", max_length=32)

    @field_validator("wallet")
    @classmethod
    def validate_wallet(cls, v: str) -> str:
        v = v.strip()
        if not _WALLET_RE.match(v):
            raise ValueError(
                "Wallet must be a valid Ethereum address (0x + 40 hex chars) "
                "or TRON address (T + 33 base58 chars)."
            )
        return v

    @field_validator("chain")
    @classmethod
    def validate_chain(cls, v: str) -> str:
        v = v.upper()
        if v not in ALLOWED_CHAINS:
            raise ValueError(f"Chain must be one of: {', '.join(ALLOWED_CHAINS)}")
        return v

# ---------------------------------------------------------------- API routes
@app.post("/api/report")
def submit_report(r: ReportIn, request: Request, bg: BackgroundTasks):
    case = build_case(r.wallet, r.chain, r.amount, r.category)
    save_case(case)
    # Log in the background — response is already on its way to the browser
    bg.add_task(log_activity, client_ip(request), "/api/report", r.wallet)
    return case

@app.get("/api/ncrp-lookup/{complaint_id}")
def ncrp_lookup(complaint_id: str):
    if len(complaint_id) > 64:
        raise HTTPException(400, "Complaint ID too long.")
    return simulated_ncrp_complaint(complaint_id)

@app.get("/api/cases")
def list_cases(bg: BackgroundTasks, request: Request):
    # Background-log page visits here now (middleware no longer does it)
    bg.add_task(log_activity, client_ip(request), "/api/cases")
    return list_recent_cases(limit=20)

@app.get("/api/case/{case_id}")
def get_case(case_id: str):
    # Sanitise: case IDs are "NCRP-" + 8 uppercase hex chars
    if not re.match(r"^NCRP-[0-9A-F]{8}$", case_id):
        raise HTTPException(400, "Invalid case ID format.")
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Case not found.")
    return case

# ---------------------------------------------------------------- pages
# Each page is one self-contained HTML file. We deliberately do NOT mount the
# whole folder as static files — that would expose app.py and cases.json.
basic_auth = HTTPBasic()

def require_owner(creds: HTTPBasicCredentials = Depends(basic_auth)):
    if not VISITORS_PASSWORD:
        raise HTTPException(500, "Set VISITORS_PASSWORD on the server first (see README).")
    if not secrets.compare_digest(creds.password, VISITORS_PASSWORD):
        raise HTTPException(401, "Wrong password", headers={"WWW-Authenticate": "Basic"})
    return True

@app.get("/visitors", response_class=HTMLResponse)
def visitors_page(_: bool = Depends(require_owner)):
    if not DATABASE_URL:
        return HTMLResponse("<p>Set DATABASE_URL on the server first (see README).</p>")
    conn = None
    try:
        conn = db_connect()
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS activity ("
                "id SERIAL PRIMARY KEY, ts TIMESTAMPTZ DEFAULT now(), "
                "ip TEXT, path TEXT, wallet TEXT)"
            )
            cur.execute("SELECT ts, ip, path, wallet FROM activity ORDER BY ts DESC LIMIT 500")
            rows = cur.fetchall()
    finally:
        db_putconn(conn)

    def esc(v): return html.escape(str(v)) if v is not None else ""
    body = "".join(
        f"<tr><td>{esc(ts.strftime('%Y-%m-%d %H:%M:%S'))}</td><td class='m'>{esc(ip)}</td>"
        f"<td>{esc(path)}</td><td class='m'>{esc(wallet) or '&ndash;'}</td></tr>"
        for ts, ip, path, wallet in rows
    )
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8">
<title>Visitors &middot; $Tracer AI</title>
<style>
body{{background:#EEE9DD;color:#1C1B18;font:15px/1.5 system-ui,Arial,sans-serif;margin:0;padding:28px}}
h1{{font:400 30px Georgia,serif;margin:0 0 4px}}
.n{{color:#6C665B;font-size:13px;margin:0 0 18px}}
table{{width:100%;border-collapse:collapse;font-size:13.5px;background:#F8F5EB;border:1px solid #D3DDEE}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid #D3DDEE}}
th{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#6C665B}}
.m{{font-family:ui-monospace,Consolas,monospace}}
</style></head><body>
<h1>Visitors</h1>
<p class="n">Last {len(rows)} events, most recent first. Owner-only page.</p>
<table><thead><tr><th>Time (UTC)</th><th>IP</th><th>Page</th><th>Wallet submitted</th></tr></thead>
<tbody>{body}</tbody></table>
</body></html>""")

@app.get("/")
def story_page(bg: BackgroundTasks, request: Request):
    bg.add_task(log_activity, client_ip(request), "/")
    return FileResponse(APP_DIR / "demo.html")

@app.get("/app")
def tool_page(bg: BackgroundTasks, request: Request):
    bg.add_task(log_activity, client_ip(request), "/app")
    return FileResponse(APP_DIR / "app.html")

@app.get("/about")
def about_page(bg: BackgroundTasks, request: Request):
    bg.add_task(log_activity, client_ip(request), "/about")
    return FileResponse(APP_DIR / "about.html")

# Lets you just double-click app.py or run "py app.py" instead of typing
# the uvicorn command by hand every time.
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
