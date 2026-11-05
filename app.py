"""
Tracer AI - minimal working prototype backend.

- Phase 1: Security hardening (connection pooling, background tasks,
  Pydantic validation, IP validation, CORS, security headers).
- Phase 2: Real blockchain API integration via Etherscan + TronGrid.
  When ETHERSCAN_API_KEY / TRONGRID_API_KEY env vars are set, the
  backend fetches real USDT transfer data and traces actual on-chain
  hops. Falls back to deterministic simulation if keys are absent or
  the wallet has no USDT activity.

Pages:
    /          scroll-driven story (demo.html) - how the system works
    /app       the working tool (app.html)     - enter or pull a report
    /visitors  password-protected activity log (owner only)

Run:
    pip install -r requirements.txt
    uvicorn app:app --reload
    open http://127.0.0.1:8000

Optional env vars for Phase 2 live chain data:
    ETHERSCAN_API_KEY   - free key from https://etherscan.io/apis
    TRONGRID_API_KEY    - free key from https://www.trongrid.io/
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

import httpx
import psycopg2
import psycopg2.pool
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field, field_validator

APP_DIR = Path(__file__).parent
DB_FILE = APP_DIR / "cases.json"
_FILE_LOCK = threading.Lock()

app = FastAPI(title="Tracer AI (prototype)")

# ---------------------------------------------------------------- CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------- env vars
DATABASE_URL       = os.environ.get("DATABASE_URL")
VISITORS_PASSWORD  = os.environ.get("VISITORS_PASSWORD")
ETHERSCAN_API_KEY  = os.environ.get("ETHERSCAN_API_KEY", "")
TRONGRID_API_KEY   = os.environ.get("TRONGRID_API_KEY", "")

# ---------------------------------------------------------------- DB connection pool
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
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        candidate = fwd.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return request.client.host if request.client else "unknown"

# ---------------------------------------------------------------- activity logging (non-blocking)
def log_activity(ip: str, path: str, wallet: str | None = None) -> None:
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

# ---------------------------------------------------------------- security headers middleware
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
    if DATABASE_URL:
        conn = None
        try:
            conn = db_connect()
            with conn.cursor() as cur:
                cur.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, data JSONB)")
                cur.execute(
                    """
                    SELECT
                        data->>'case_id',
                        (data->>'created_at')::bigint,
                        data->'input'->>'wallet',
                        data->'vasp'->>'name',
                        (data->'vasp'->>'confidence')::float,
                        (data->'summary'->>'funds_reached_exchange')::float,
                        COALESCE(data->>'data_source', 'simulated')
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
                        "vasp": r[3], "confidence": r[4],
                        "funds_reached_exchange": r[5], "data_source": r[6],
                    }
                    for r in rows
                ]
        except Exception as e:
            print("list_recent_cases: DB unavailable, falling back to file ->", e)
        finally:
            db_putconn(conn)
    cases = list(_file_db().values())
    cases.sort(key=lambda c: -c.get("created_at", 0))
    return [
        {
            "case_id": c["case_id"], "created_at": c["created_at"],
            "wallet": c["input"]["wallet"], "vasp": c["vasp"]["name"],
            "confidence": c["vasp"]["confidence"],
            "funds_reached_exchange": c["summary"]["funds_reached_exchange"],
            "data_source": c.get("data_source", "simulated"),
        }
        for c in cases[:limit]
    ]

# ---------------------------------------------------------------- helpers
def fake_address(rng: random.Random, chain: str) -> str:
    if chain == "TRX":
        alphabet = string.ascii_letters + string.digits
        return "T" + "".join(rng.choice(alphabet) for _ in range(33))
    alphabet = "0123456789abcdef"
    return "0x" + "".join(rng.choice(alphabet) for _ in range(40))

def short(addr: str) -> str:
    return addr[:6] + "\u2026" + addr[-4:]

VASP_POOL = ["ExampleX Exchange", "CoinHarbor", "NovaTrade", "ZenithSwap"]
CATEGORY_POOL = [
    "Investment scam", "Task-based fraud", "Sextortion",
    "Phishing", "Ransomware", "Romance scam",
]
ALLOWED_CHAINS = {"ETH", "TRX"}

# ---------------------------------------------------------------- risk model
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
NODE_LEVEL = {
    "victim": 0, "reported": 1, "burner": 2, "mixer": 3,
    "bridge": 3, "deposit": 4, "hotwallet": 5, "fiat": 6,
}

# ================================================================
#  PHASE 2 — REAL BLOCKCHAIN API INTEGRATION
# ================================================================

# USDT contract addresses on each chain
USDT_ETH = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDT_TRX = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

# Known exchange hot wallet addresses (lowercase for ETH, original for TRX).
# This is a curated lookup list; real production systems use cluster databases.
KNOWN_VASPS: dict[str, str] = {
    # Binance ETH
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance",
    "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8": "Binance",
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": "Binance",
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance",
    # Coinbase ETH
    "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43": "Coinbase",
    "0x71660c4005ba85c37ccec55d0c4493e66fe775d3": "Coinbase",
    # Kraken ETH
    "0x2910543af39aba0cd09dbb2d50200b3e800a63d2": "Kraken",
    "0x0a869d79a7052c7f1b55a8ebabbea3420f0d1e13": "Kraken",
    # OKX ETH
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": "OKX",
    "0x236f9f97e0e62388479bf9e5ba4889e46b0273c3": "OKX",
    # Huobi / HTX ETH
    "0xab5c66752a9e8167967685f1450532fb96d5d24f": "Huobi (HTX)",
    "0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b": "Huobi (HTX)",
    # Bybit ETH
    "0xf89d7b9c864f589bbf53a82105107622b35eaa40": "Bybit",
    # KuCoin ETH
    "0xd6216fc19db775df9774a6e33526131da7d19a2c": "KuCoin",
    # Binance TRX (lowercase for consistency)
    "tn3w4h6rk2ce4vx9ynfqhwkennhjoxb3m9": "Binance",
    "tbnbdepositaddress1yqnqp45m6xkqs": "Binance",
    # Huobi TRX
    "tnaraoluyeyev2uf7gcplrvmbkrw8takfwh": "Huobi (HTX)",
    # OKX TRX
    "tdudfttxp7c4yqygrst5t9tsevjvfvevmy": "OKX",
}

# Known Ethereum mixer/tumbler contract addresses
KNOWN_MIXERS_ETH: set[str] = {
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",  # Tornado Cash 0.1 ETH
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",  # Tornado Cash 1 ETH
    "0xa160cdab225685da1d56aa342ad8841c3b53f291",  # Tornado Cash 10 ETH
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",  # Tornado Cash 100 ETH
    "0x07687e702b410fa43f4cb4af7fa097918ffd2730",  # ChipMixer
    "0x23773e65ed146a459667e3e2093f7b1f28ece8a7",  # Sinbad.io
}

# ---------------------------------------------------------------- Etherscan API
def _fetch_etherscan(address: str, timeout: int = 7) -> list[dict]:
    """
    Fetch USDT ERC-20 token transfers for an ETH address.
    Returns [] if key is absent, API fails, or no USDT activity.
    """
    if not ETHERSCAN_API_KEY:
        return []
    url = (
        "https://api.etherscan.io/api"
        f"?module=account&action=tokentx"
        f"&address={address}"
        f"&contractaddress={USDT_ETH}"
        f"&sort=asc&offset=100&page=1"
        f"&apikey={ETHERSCAN_API_KEY}"
    )
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url)
            data = resp.json()
            if data.get("status") == "1":
                return data.get("result", [])
            # status "0" can mean no txs (not an error), or rate-limited
            msg = data.get("message", "")
            if "No transactions" in msg or data.get("result") == []:
                return []
            print(f"Etherscan non-OK status for {address}: {data.get('message')}")
    except Exception as e:
        print(f"Etherscan fetch error ({address}): {e}")
    return []

# ---------------------------------------------------------------- TronGrid API
def _fetch_trongrid(address: str, timeout: int = 7) -> list[dict]:
    """
    Fetch USDT TRC-20 transfers for a TRON address.
    Returns [] if key absent, fails, or no USDT activity.
    """
    url = (
        f"https://api.trongrid.io/v1/accounts/{address}/transactions/trc20"
        f"?limit=50&contract_address={USDT_TRX}&order_by=block_timestamp,asc"
    )
    headers = {}
    if TRONGRID_API_KEY:
        headers["TRON-PRO-API-KEY"] = TRONGRID_API_KEY
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers=headers)
            return resp.json().get("data", [])
    except Exception as e:
        print(f"TronGrid fetch error ({address}): {e}")
    return []

# ---------------------------------------------------------------- helpers for real data
def _tx_timestamp(tx: dict, chain: str) -> int:
    """Normalise block timestamp to Unix seconds across both chains."""
    if chain == "TRX":
        # TronGrid returns milliseconds
        return int(tx.get("block_timestamp", 0)) // 1000
    return int(tx.get("timeStamp", 0))

def _tx_amount_usdt(tx: dict, chain: str) -> float:
    """Return USDT amount in human units (not raw integer)."""
    if chain == "TRX":
        # TronGrid value field is already a string of raw sun; USDT TRC-20 has 6 decimals
        return float(tx.get("value", 0)) / 1_000_000
    # Etherscan: tokenDecimal is 6 for USDT
    decimals = int(tx.get("tokenDecimal", 6))
    return float(tx.get("value", 0)) / (10 ** decimals)

def _tx_from(tx: dict) -> str:
    return tx.get("from", tx.get("from_address", "")).lower()

def _tx_to(tx: dict) -> str:
    return tx.get("to", tx.get("to_address", "")).lower()

def _fetch_transfers(address: str, chain: str) -> list[dict]:
    if chain == "TRX":
        return _fetch_trongrid(address)
    return _fetch_etherscan(address)

def _split_io(txs: list[dict], address: str, chain: str) -> tuple[list, list]:
    """Split a transfer list into inbound and outbound relative to address."""
    addr = address.lower()
    ins  = [t for t in txs if _tx_to(t)   == addr]
    outs = [t for t in txs if _tx_from(t) == addr]
    return ins, outs

def _compute_real_features(
    address: str,
    chain: str,
    txs_in: list,
    txs_out: list,
    first_ts: int,
    now_ts: int,
) -> dict:
    """
    Derive the same 8 risk features used by the model, but from real
    on-chain data instead of hand-set constants.
    """
    feats: dict[str, float] = {}
    addr_lower = address.lower()

    # inflow: multiple distinct senders → money collection behaviour
    unique_senders = len({_tx_from(t) for t in txs_in})
    feats["inflow"] = min(1.0, unique_senders / 5.0)

    # speed: how quickly funds leave after arriving
    if txs_in and txs_out:
        earliest_in  = min(_tx_timestamp(t, chain) for t in txs_in)
        earliest_out = min(_tx_timestamp(t, chain) for t in txs_out)
        if earliest_out > earliest_in:
            delta_hours = (earliest_out - earliest_in) / 3600
            # <6 h = very fast (1.0), >48 h = slow (0.0)
            feats["speed"] = max(0.0, min(1.0, 1.0 - delta_hours / 48.0))
        else:
            feats["speed"] = 0.95  # out before in means same block → extremely fast

    # fanOut: many unique recipients
    unique_recipients = len({_tx_to(t) for t in txs_out})
    feats["fanOut"] = min(1.0, unique_recipients / 8.0)

    # mixer: sends to a known mixer
    if chain == "ETH":
        out_addrs = {_tx_to(t) for t in txs_out}
        feats["mixer"] = 1.0 if out_addrs & KNOWN_MIXERS_ETH else 0.0

    # fresh: wallet age < 90 days at time of first transaction
    if first_ts > 0:
        age_days = (now_ts - first_ts) / 86400
        feats["fresh"] = max(0.0, min(1.0, 1.0 - age_days / 90.0))

    # split: coefficient of variation in outgoing amounts (irregular splitting = suspicious)
    out_amounts = [_tx_amount_usdt(t, chain) for t in txs_out if _tx_amount_usdt(t, chain) > 0]
    if len(out_amounts) > 1:
        avg = sum(out_amounts) / len(out_amounts)
        if avg > 0:
            std = math.sqrt(sum((a - avg) ** 2 for a in out_amounts) / len(out_amounts))
            feats["split"] = min(1.0, (std / avg) / 2.0)

    # service: recognised VASP hot wallet
    if addr_lower in KNOWN_VASPS:
        feats["service"] = 0.97

    return feats

def _classify_wallet(
    address: str,
    chain: str,
    txs_in: list,
    txs_out: list,
    first_ts: int,
    now_ts: int,
) -> str:
    """
    Classify a real wallet into one of the graph node types.
    Priority: known VASP > known mixer > heuristic rules.
    """
    addr_lower = address.lower()

    if addr_lower in KNOWN_VASPS:
        # Many deposits sweep into this address → it's the hot wallet
        return "hotwallet" if len(txs_in) > 3 else "deposit"

    if chain == "ETH" and addr_lower in KNOWN_MIXERS_ETH:
        return "mixer"

    unique_out = len({_tx_to(t) for t in txs_out})
    unique_in  = len({_tx_from(t) for t in txs_in})

    # Very high fan-out from a single address: exchange hot wallet behaviour
    if unique_out > 20:
        return "hotwallet"

    # Short-lived wallet that quickly passes funds on → burner / layering
    age_days = max(0, (now_ts - first_ts) / 86400) if first_ts else 365
    if age_days < 30 and len(txs_out) > 0 and unique_out <= 5:
        return "burner"

    # Destination for funds with outgoing sweeps → deposit address
    if len(txs_in) > 0 and len(txs_out) > 0:
        return "deposit"

    return "deposit"  # safe default

# ---------------------------------------------------------------- real case builder
def build_case_real(wallet: str, chain: str, amount: float, category: str) -> dict | None:
    """
    Build a trace case using real on-chain USDT transfer data.

    Returns None if:
      - No API key is configured for this chain
      - The wallet has no USDT transfer activity
      - We can't form a meaningful graph (< 1 outflow)

    The caller falls back to build_case() (simulation) in those situations.
    """
    # Quick exit if no API key for this chain
    if chain == "ETH" and not ETHERSCAN_API_KEY:
        return None
    if chain == "TRX" and not TRONGRID_API_KEY:
        return None

    now_ts = int(time.time())

    # ---- Step 1: fetch reported wallet transfers ----
    reported_txs = _fetch_transfers(wallet, chain)
    if not reported_txs:
        print(f"build_case_real: no USDT activity for {wallet} on {chain}")
        return None

    txs_in, txs_out = _split_io(reported_txs, wallet, chain)
    if not txs_out:
        print(f"build_case_real: no outflows from {wallet}")
        return None

    # ---- Step 2: graph structure ----
    nodes: list[dict] = []
    edges: list[dict] = []
    nid   = [0]

    def make_node(ntype: str, addr: str, nchain: str, feats: dict | None = None) -> dict:
        nid[0] += 1
        if feats is None:
            rng = random.Random(hashlib.sha256(addr.encode()).hexdigest())
            feats = TYPE_FEATURES.get(ntype, TYPE_FEATURES["deposit"])(rng)
        p, contribs = score(feats)
        n = {
            "id":        f"n{nid[0]}",
            "type":      ntype,
            "chain":     nchain,
            "address":   addr,
            "label":     TYPE_ROLE.get(ntype, ntype),
            "short":     short(addr) if addr != "fiat" else "fiat",
            "risk":      round(p * 100),
            "reasons":   contribs,
            "top_reasons": contribs[:3],
        }
        nodes.append(n)
        return n

    def add_edge(a: dict, b: dict, amt: float) -> None:
        edges.append({"from": a["id"], "to": b["id"], "amount": round(amt, 2)})

    # ---- Reported wallet (L1) ----
    first_ts = _tx_timestamp(reported_txs[0], chain)
    reported_feats = _compute_real_features(wallet, chain, txs_in, txs_out, first_ts, now_ts)
    # Ensure reported node always looks like it received victim funds
    reported_feats.setdefault("inflow", 0.9)
    reported = make_node("reported", wallet, chain, reported_feats)

    # ---- Victims (L0) — real senders ----
    total_in = 0.0
    seen_senders: set[str] = set()
    for tx in txs_in[:4]:                      # cap at 4 victims for display clarity
        sender = _tx_from(tx)
        if not sender or sender in seen_senders:
            continue
        seen_senders.add(sender)
        amt = _tx_amount_usdt(tx, chain)
        if amt <= 0:
            continue
        v = make_node("victim", sender, chain, {})   # victims have no risk score
        nodes[-1].pop("risk", None)
        nodes[-1].pop("reasons", None)
        nodes[-1].pop("top_reasons", None)
        add_edge(v, reported, amt)
        total_in += amt

    if total_in <= 0:
        total_in = amount          # use submitted amount if no real inflow amounts found

    # ---- Outflows from reported wallet (L2–L4): follow up to 3 hops ----
    # Sort by amount descending, cap at 4 outflows to stay within API rate limits
    sorted_out = sorted(txs_out, key=lambda t: _tx_amount_usdt(t, chain), reverse=True)[:4]
    deposits:   list[tuple[dict, float]] = []
    vasp_name:  str | None               = None

    for tx in sorted_out:
        dest      = _tx_to(tx)
        out_amt   = _tx_amount_usdt(tx, chain)
        dest_orig = tx.get("to", tx.get("to_address", dest))  # preserve original casing for TRX

        if not dest or out_amt <= 0:
            continue

        # --- Is destination a known VASP directly? ---
        if dest in KNOWN_VASPS:
            vasp_name = vasp_name or KNOWN_VASPS[dest]
            hot = make_node("hotwallet", dest_orig, chain)
            add_edge(reported, hot, out_amt)
            deposits.append((hot, out_amt))
            continue

        # --- Is destination a known mixer? ---
        if chain == "ETH" and dest in KNOWN_MIXERS_ETH:
            mx = make_node("mixer", dest_orig, chain)
            add_edge(reported, mx, out_amt)
            # Treat mixer as a terminal node for display (don't go deeper)
            deposits.append((mx, out_amt * 0.97))
            continue

        # --- Fetch one more hop (L3) ---
        hop_txs = _fetch_transfers(dest_orig, chain)
        hop_in, hop_out = _split_io(hop_txs, dest, chain)
        hop_first_ts    = _tx_timestamp(hop_txs[0], chain) if hop_txs else now_ts
        hop_feats       = _compute_real_features(dest, chain, hop_in, hop_out, hop_first_ts, now_ts)
        hop_type        = _classify_wallet(dest, chain, hop_in, hop_out, hop_first_ts, now_ts)
        hop_node        = make_node(hop_type, dest_orig, chain, hop_feats)
        add_edge(reported, hop_node, out_amt)

        if hop_type in ("deposit", "hotwallet"):
            if hop_type == "hotwallet" and dest in KNOWN_VASPS:
                vasp_name = vasp_name or KNOWN_VASPS[dest]
            deposits.append((hop_node, out_amt))
        else:
            # burner/mixer/bridge — go one more level (L4)
            if hop_out:
                next_tx   = max(hop_out, key=lambda t: _tx_amount_usdt(t, chain))
                next_dest = _tx_to(next_tx)
                next_orig = next_tx.get("to", next_tx.get("to_address", next_dest))
                next_amt  = _tx_amount_usdt(next_tx, chain)

                if next_dest and next_amt > 0:
                    # Check if final dest is VASP
                    if next_dest in KNOWN_VASPS:
                        vasp_name = vasp_name or KNOWN_VASPS[next_dest]
                        final = make_node("hotwallet", next_orig, chain)
                    else:
                        # Fetch L4 to decide type
                        l4_txs = _fetch_transfers(next_orig, chain)
                        l4_in, l4_out = _split_io(l4_txs, next_dest, chain)
                        l4_ts   = _tx_timestamp(l4_txs[0], chain) if l4_txs else now_ts
                        l4_type = _classify_wallet(next_dest, chain, l4_in, l4_out, l4_ts, now_ts)
                        l4_feats = _compute_real_features(next_dest, chain, l4_in, l4_out, l4_ts, now_ts)
                        final = make_node(l4_type, next_orig, chain, l4_feats)
                        if l4_type == "hotwallet" and next_dest in KNOWN_VASPS:
                            vasp_name = vasp_name or KNOWN_VASPS[next_dest]

                    add_edge(hop_node, final, next_amt)
                    deposits.append((final, next_amt))

    if not deposits:
        print("build_case_real: couldn't build meaningful graph (no deposits found)")
        return None

    # ---- Fiat off-ramp (L6) ----
    fiat = {
        "id": f"n{nid[0]+1}", "type": "fiat", "chain": "", "address": "fiat",
        "label": TYPE_ROLE["fiat"], "short": "fiat",
    }
    nid[0] += 1
    nodes.append(fiat)

    total_reached = sum(amt for _, amt in deposits)

    # Find or create a hot wallet to connect to fiat
    hot_nodes = [n for n in nodes if n["type"] == "hotwallet"]
    if hot_nodes:
        # Connect largest hot wallet to fiat
        largest_hot = hot_nodes[0]
        add_edge(largest_hot, fiat, total_reached)
    else:
        # Promote highest-volume deposit to hot wallet for display
        biggest_dep, biggest_amt = max(deposits, key=lambda x: x[1])
        biggest_dep["type"]  = "hotwallet"
        biggest_dep["label"] = TYPE_ROLE["hotwallet"]
        add_edge(biggest_dep, fiat, biggest_amt)
        hot_nodes = [biggest_dep]

    hot_short = hot_nodes[0]["short"]
    vasp_name = vasp_name or "Unidentified Exchange"

    # ---- Confidence & evidence ----
    named_vasp    = vasp_name != "Unidentified Exchange"
    n_hops        = max((NODE_LEVEL.get(n["type"], 0) for n in nodes), default=5)
    real_dep_count = len([n for n, _ in deposits])
    confidence    = round(
        min(97.0, 68.0
            + (15.0 if named_vasp else 0.0)
            + min(10.0, real_dep_count * 2.5)
            + (4.0 if n_hops >= 4 else 0.0)),
        1,
    )
    share = round(total_reached / total_in * 100) if total_in > 0 else 0
    dep_display = [n for n, _ in deposits]
    evidence = [
        f"{real_dep_count} real outflow path(s) traced from the reported wallet (live chain data)",
        f"~{share}% of reported funds have left the wallet on-chain",
    ]
    if named_vasp:
        evidence.append(f"Destination cluster matches known VASP: {vasp_name}")
    evidence.append(
        f"Destination wallets: {', '.join(n['short'] for n in dep_display[:3])}"
    )

    case_id = "NCRP-" + uuid.uuid4().hex[:8].upper()
    return {
        "case_id":     case_id,
        "created_at":  now_ts,
        "data_source": "live",           # <-- frontend uses this for the badge
        "input":       {"wallet": wallet, "chain": chain, "amount": amount, "category": category},
        "summary": {
            "wallets_found":          len(nodes),
            "hops":                   n_hops,
            "chains":                 sorted({n["chain"] for n in nodes if n["chain"]}),
            "funds_reported":         round(total_in, 2),
            "funds_reached_exchange": round(total_reached, 2),
        },
        "nodes": nodes,
        "edges": edges,
        "vasp":  {
            "name":       vasp_name,
            "confidence": confidence,
            "wallet":     hot_short,
            "evidence":   evidence,
        },
        "freeze_request": (
            f"DRAFT \u2014 for investigators only (LIVE CHAIN DATA)\n\n"
            f"Authority: Sec. 94 BNSS 2023 / Sec. 91 CrPC | Sec. 106 BNSS / Sec. 102 CrPC\n\n"
            f"To: {vasp_name} Compliance & Legal Team\n"
            f"From: [Investigating Officer Name]\n"
            f"Station / Cyber Cell: [Police Station / Cyber Crime Cell]\n"
            f"FIR / NCRP Ref: {case_id}\n\n"
            f"Subject: Request to Freeze Accounts & Preserve KYC Records\n\n"
            f"Reported wallet: {wallet}\n"
            f"Outflow wallets: " + ", ".join(n["short"] for n in dep_display[:5]) + f"\n"
            f"Hot wallet cluster: {hot_short}\n"
            f"Funds traced on-chain: {round(total_reached, 2)} USDT\n"
            f"Attribution confidence: {confidence}%\n"
            f"Fraud category: {category}\n\n"
            f"You are hereby requested under the above provisions to:\n"
            f"  1. Immediately freeze all accounts linked to the above addresses.\n"
            f"  2. Preserve full KYC records, transaction logs, and IP/device data.\n"
            f"  3. Respond within 7 working days with account holder details.\n\n"
            f"Data source: Live on-chain data via Etherscan / TronGrid APIs."
        ),
    }

# ================================================================
#  SIMULATION FALLBACK (unchanged, now tags data_source: simulated)
# ================================================================
def build_case(wallet: str, chain: str, amount: float, category: str) -> dict:
    seed = hashlib.sha256(wallet.encode()).hexdigest()
    rng  = random.Random(seed)

    nodes, edges = [], []
    nid = [0]
    def add_node(type_, addr, chain_):
        nid[0] += 1
        n = {
            "id": f"n{nid[0]}", "type": type_, "chain": chain_, "address": addr,
            "label": TYPE_ROLE[type_], "short": short(addr) if addr != "fiat" else "fiat",
        }
        if type_ in TYPE_FEATURES:
            feats = TYPE_FEATURES[type_](rng)
            p, contribs = score(feats)
            n["risk"]        = round(p * 100)
            n["reasons"]     = contribs
            n["top_reasons"] = contribs[:3]
        nodes.append(n)
        return n

    def add_edge(a, b, amt):
        edges.append({"from": a["id"], "to": b["id"], "amount": round(amt, 2)})

    reported = add_node("reported", wallet, chain)
    n_victims = rng.randint(1, 3)
    victim_amounts = [amount] + [round(amount * rng.uniform(.3, 1.4), 2) for _ in range(n_victims - 1)]
    for va in victim_amounts:
        v = add_node("victim", fake_address(rng, "ETH"), "ETH")
        add_edge(v, reported, va)
    total_in = sum(victim_amounts)

    n_burn = rng.randint(2, 3)
    splits = [rng.uniform(.6, 1.4) for _ in range(n_burn)]
    ssum   = sum(splits)
    burners = []
    for s in splits:
        amt = total_in * (s / ssum) * rng.uniform(.9, .98)
        b   = add_node("burner", fake_address(rng, chain), chain)
        add_edge(reported, b, amt)
        burners.append((b, amt))

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

    hot = add_node("hotwallet", fake_address(rng, chain), chain)
    total_reached = 0.0
    for d, amt in deposits:
        add_edge(d, hot, amt)
        total_reached += amt
    fiat = add_node("fiat", "fiat", "")
    add_edge(hot, fiat, total_reached)

    vasp_name  = rng.choice(VASP_POOL)
    confidence = round(rng.uniform(84, 97), 1)
    dep_nodes  = [d for d, _ in deposits]
    avg_dep_risk = round(sum(d["risk"] for d in dep_nodes) / len(dep_nodes))
    share = round(total_reached / total_in * 100)
    evidence = [
        f"{len(deposits)} separate paths end in deposit addresses that sweep into one hot wallet",
        f"{share}% of the reported funds reached this single cluster",
        f"Deposit and hot wallets look like a regulated service (avg laundering risk {avg_dep_risk}%)",
    ]

    case_id = "NCRP-" + uuid.uuid4().hex[:8].upper()
    return {
        "case_id":     case_id,
        "created_at":  int(time.time()),
        "data_source": "simulated",      # <-- tells frontend to show Simulated badge
        "input":       {"wallet": wallet, "chain": chain, "amount": amount, "category": category},
        "summary": {
            "wallets_found":          len(nodes),
            "hops":                   5,
            "chains":                 sorted({n["chain"] for n in nodes if n["chain"]}),
            "funds_reported":         round(total_in, 2),
            "funds_reached_exchange": round(total_reached, 2),
        },
        "nodes":  nodes,
        "edges":  edges,
        "vasp":   {"name": vasp_name, "confidence": confidence, "wallet": hot["short"], "evidence": evidence},
        "freeze_request": (
            f"DRAFT \u2014 for investigators only (simulated)\n\n"
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
            f"* Fictional exchange name \u2014 for demo purposes only."
        ),
    }

# ---------------------------------------------------------------- simulated NCRP lookup
def simulated_ncrp_complaint(complaint_id: str) -> dict:
    rng   = random.Random(hashlib.sha256(complaint_id.encode()).hexdigest())
    chain = rng.choice(["ETH", "TRX"])
    return {
        "complaint_id":  complaint_id,
        "category":      rng.choice(CATEGORY_POOL),
        "amount":        rng.choice([4500, 8200, 12000, 18500, 25000, 31000]),
        "chain":         chain,
        "wallet":        fake_address(rng, chain),
        "filed_days_ago": rng.randint(0, 6),
    }

# ---------------------------------------------------------------- input model
_WALLET_RE = re.compile(r"^(0x[0-9a-fA-F]{40}|T[1-9A-HJ-NP-Za-km-z]{33})$")

class ReportIn(BaseModel):
    wallet:   str   = Field(..., min_length=26, max_length=66)
    chain:    str   = Field("ETH", max_length=8)
    amount:   float = Field(5000, ge=1, le=1_000_000_000)
    category: str   = Field("Investment scam", max_length=64)
    source:   str   = Field("manual", max_length=32)

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
    """
    Try live blockchain data first; fall back to simulation.
    The response always includes data_source: 'live' | 'simulated'
    so the frontend can show the appropriate badge.
    """
    case = None
    try:
        case = build_case_real(r.wallet, r.chain, r.amount, r.category)
    except Exception as e:
        print(f"build_case_real failed ({r.wallet}): {e}")

    if case is None:
        case = build_case(r.wallet, r.chain, r.amount, r.category)

    save_case(case)
    bg.add_task(log_activity, client_ip(request), "/api/report", r.wallet)
    return case

@app.get("/api/status")
def api_status():
    """Reports which live chain APIs are configured — useful for the frontend badge."""
    return {
        "etherscan": bool(ETHERSCAN_API_KEY),
        "trongrid":  bool(TRONGRID_API_KEY),
        "database":  bool(DATABASE_URL),
    }

@app.get("/api/ncrp-lookup/{complaint_id}")
def ncrp_lookup(complaint_id: str):
    if len(complaint_id) > 64:
        raise HTTPException(400, "Complaint ID too long.")
    return simulated_ncrp_complaint(complaint_id)

@app.get("/api/cases")
def list_cases(bg: BackgroundTasks, request: Request):
    bg.add_task(log_activity, client_ip(request), "/api/cases")
    return list_recent_cases(limit=20)

@app.get("/api/case/{case_id}")
def get_case(case_id: str):
    if not re.match(r"^NCRP-[0-9A-F]{8}$", case_id):
        raise HTTPException(400, "Invalid case ID format.")
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPException(404, "Case not found.")
    return case

# ---------------------------------------------------------------- pages
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
