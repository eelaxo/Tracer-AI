# $Tracer AI: working prototype

Three pages, one backend, one theme.

| URL | What it is |
|---|---|
| `/` | Scroll-driven story: how a wallet report becomes a named exchange |
| `/app` | The working tool: enter a wallet or pull one from NCRP*, watch it get traced |
| `/about` | Team page: Stratagem Crew, Team ID 176962 |
| `/visitors` | Owner-only activity log: page visits + submitted wallet addresses |

**Real vs simulated:** the web app, API and storage are real. There is no live
blockchain or NCRP connection. The wallet graph is generated deterministically
from the address you type (same address gives the same graph), and the NCRP
lookup and exchange names are simulated.

## Run it (Windows)

```
py -m pip install -r requirements.txt
py -m uvicorn app:app --reload
```

Then open http://127.0.0.1:8000. Other systems: use `python3` instead of `py`.

Double-clicking `start.bat` does the same thing without typing anything.

## Files

- `app.py`: FastAPI backend (report intake, trace generator, risk scoring,
  exchange attribution, freeze-request draft, visitor logging)
- `demo.html` / `app.html` / `about.html`: the three pages above
- `start.bat`: double-click to run on Windows, no terminal typing needed

The pages use Google Fonts (Instrument Serif, IBM Plex, Caveat). Offline they
fall back to Georgia and system fonts and still work; connect to the internet
once before presenting if you want the exact look.

## Setting up `/visitors` (needs two things, both optional locally)

Without them, the site still works fine — `/visitors` just shows a setup
message instead of data. Both are **environment variables**, not anything
typed into the code, so your password never ends up on public GitHub.

**1. A free Postgres database, so visitor history survives Render restarts.**
`cases.json` resets whenever Render's free tier restarts your service;
Postgres doesn't. Pick one (both are free, no credit card):

- **Supabase** (supabase.com) → New project → Settings → Database →
  copy the "Connection string" (URI format)
- **Neon** (neon.tech) → New project → copy the connection string shown
  on the dashboard

**2. A password you choose, for the `/visitors` page itself.**
Just make one up — there's no account system, it's a single shared password.

**Setting them:**

- **Locally:** set them in your terminal before starting the server:
  ```
  set DATABASE_URL=postgresql://...your connection string...
  set VISITORS_PASSWORD=yourpasswordhere
  py -m uvicorn app:app --reload
  ```
  (On Mac/Linux use `export` instead of `set`.)
- **On Render:** your service → Environment tab → Add Environment Variable →
  add `DATABASE_URL` and `VISITORS_PASSWORD` there. Render restarts the
  service automatically after you save.

Then visit `/visitors` — your browser will prompt for a username (type
anything) and the password you set.

## Reset the demo

Stop the server and delete `cases.json` to clear "recent cases" (local only;
on Render this already resets on its own). To clear visitor history instead,
delete the `activity` table from your Postgres dashboard, or run
`DELETE FROM activity;` in its SQL editor.

## Swap-in points for a real version

- `build_case()` in `app.py`: replace with real chain indexing
- `score()`: replace the hand-set weights with a trained model
- `simulated_ncrp_complaint()` / `/api/ncrp-lookup`: replace with a real NCRP/SAHYOG integration
- `cases.json`: also move to Postgres, same as `/visitors` now does, if you
  want case history to survive restarts too
