"""
Tracer AI - minimal working prototype backend.

- No real blockchain calls: the "indexer" generates a plausible,
  DETERMINISTIC transaction graph from whatever wallet address is
  submitted (same input -> same graph, like a real lookup would be).
- Risk scoring is a small transparent weighted formula (documented
  in the pitch deck) instead of a trained model.
- Storage is a single JSON file (cases.json) - good enough for a
  hackathon demo, zero setup, survives restarts.

Pages:
    /     scroll-driven story (demo.html) - how the system works
    /app  the working tool (app.html)     - enter or pull a report

Run:
    pip install -r requirements.txt
    uvicorn app:app --reload
    open http://127.0.0.1:8000
"""
import hashlib
import json
import math
import random
import string
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

APP_DIR = Path(__file__).parent
DB_FILE = APP_DIR / "cases.json"

app = FastAPI(title="Tracer AI (prototype)")

# ---------------------------------------------------------------- storage
def load_db() -> dict:
    if DB_FILE.exists():
        return json.loads(DB_FILE.read_text())
    return {}

def save_db(db: dict) -> None:
    DB_FILE.write_text(json.dumps(db, indent=2))

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
            f"DRAFT \u2014 for investigators only (simulated)\n\n"
            f"To: {vasp_name} compliance team*\n"
            f"Case: {case_id}\n"
            f"Deposit wallets: " + ", ".join(d["short"] for d, _ in deposits) + f"\n"
            f"Hot wallet: {hot['short']}\n"
            f"Funds reaching exchange: {round(total_reached, 2)} USDT\n"
            f"Confidence: {confidence}%\n"
            f"Ask: freeze pending accounts, preserve KYC + transaction logs\n\n"
            f"* Fictional exchange name, for demo purposes only."
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

# ---------------------------------------------------------------- API
class ReportIn(BaseModel):
    wallet: str
    chain: str = "ETH"
    amount: float = 5000
    category: str = "Investment scam"
    source: str = "manual"

@app.post("/api/report")
def submit_report(r: ReportIn):
    wallet = r.wallet.strip()
    if len(wallet) < 4:
        raise HTTPException(400, "Wallet address looks too short.")
    case = build_case(wallet, r.chain.upper(), max(r.amount, 1), r.category)
    db = load_db()
    db[case["case_id"]] = case
    save_db(db)
    return case

@app.get("/api/ncrp-lookup/{complaint_id}")
def ncrp_lookup(complaint_id: str):
    return simulated_ncrp_complaint(complaint_id)

@app.get("/api/cases")
def list_cases():
    db = load_db()
    rows = [
        {
            "case_id": c["case_id"], "created_at": c["created_at"],
            "wallet": c["input"]["wallet"], "vasp": c["vasp"]["name"],
            "confidence": c["vasp"]["confidence"],
            "funds_reached_exchange": c["summary"]["funds_reached_exchange"],
        }
        for c in db.values()
    ]
    rows.sort(key=lambda x: -x["created_at"])
    return rows

@app.get("/api/case/{case_id}")
def get_case(case_id: str):
    db = load_db()
    if case_id not in db:
        raise HTTPException(404, "Case not found.")
    return db[case_id]

# ---------------------------------------------------------------- pages
# Each page is one self-contained HTML file. We deliberately do NOT mount the
# whole folder as static files - that would expose app.py and cases.json.
@app.get("/")
def story_page():
    return FileResponse(APP_DIR / "demo.html")

@app.get("/app")
def tool_page():
    return FileResponse(APP_DIR / "app.html")

@app.get("/about")
def about_page():
    return FileResponse(APP_DIR / "about.html")
