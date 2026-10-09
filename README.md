# $Tracer AI: working prototype

Two pages, one backend, one theme.

| URL | What it is |
|---|---|
| `/` | Scroll-driven story: how a wallet report becomes a named exchange |
| `/app` | The working tool: enter a wallet or pull one from NCRP*, watch it get traced |

**Real vs simulated:** the web app, API and storage are real. There is no live
blockchain or NCRP connection. The wallet graph is generated deterministically
from the address you type (same address gives the same graph), and the NCRP
lookup and exchange names are simulated.

## Run it (Windows)

```
py -m pip install -r requirements.txt
py -m uvicorn app:app --reload
```

Then open http://127.0.0.1:8000 (story) or http://127.0.0.1:8000/app (tool).
Other systems: use `python3` instead of `py`.

## Files

- `app.py`: FastAPI backend (report intake, trace generator, risk scoring,
  exchange attribution, freeze-request draft, `cases.json` storage)
- `demo.html`: the scroll story (served at `/`)
- `app.html`: the live tool (served at `/app`)

The pages use Google Fonts (Instrument Serif, IBM Plex, Caveat). Offline they
fall back to Georgia and system fonts and still work; connect to the internet
once before presenting if you want the exact look.

## Reset the demo

Stop the server and delete `cases.json` to clear "recent cases".

## Swap-in points for a real version

- `build_case()` in `app.py`: replace with real chain indexing
- `score()`: replace the hand-set weights with a trained model
- `simulated_ncrp_complaint()` / `/api/ncrp-lookup`: replace with a real NCRP/SAHYOG integration
- `cases.json`: replace with Postgres / Neo4j
