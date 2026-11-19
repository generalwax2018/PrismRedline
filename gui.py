"""
PrisimRedline GUI
Simple local web interface for phase status, scope, and scan progress.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn
from pathlib import Path
import json

app = FastAPI(title="PrisimRedline")

BASE = Path(__file__).parent

def load_json(name: str, default):
    p = BASE / name
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text())
    except Exception:
        return default

@app.get("/", response_class=HTMLResponse)
async def index():
    phase = load_json("phase.json", {"current": 1, "name": "1. Pre-Engagement & Scoping"})
    scope = load_json("scope.json", {"allowed": []})
    state = load_json("state.json", {"hosts": {}, "scans": []})
    hosts = list(state.get("hosts", {}).keys())

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PrisimRedline</title>
        <meta charset="utf-8">
        <style>
            body {{ font-family: system-ui, sans-serif; background: #0f1115; color: #e6e6e6; margin: 2rem; }}
            h1 {{ color: #7dd3fc; }}
            .card {{ background: #1a1d24; padding: 1rem 1.5rem; border-radius: 8px; margin-bottom: 1rem; }}
            .phase {{ font-size: 1.2rem; color: #86efac; }}
            ul {{ margin: 0.5rem 0; }}
            .muted {{ color: #9ca3af; }}
        </style>
    </head>
    <body>
        <h1>PrisimRedline</h1>
        <div class="card">
            <div class="muted">Current Phase</div>
            <div class="phase">{phase.get("name", "Unknown")}</div>
        </div>
        <div class="card">
            <div class="muted">Scope</div>
            <ul>
                {"".join(f"<li>{a}</li>" for a in scope.get("allowed", [])) or "<li class='muted'>None defined</li>"}
            </ul>
        </div>
        <div class="card">
            <div class="muted">Hosts Discovered ({len(hosts)})</div>
            <ul>
                {"".join(f"<li>{h}</li>" for h in hosts[:20]) or "<li class='muted'>None yet</li>"}
            </ul>
        </div>
        <p class="muted">Run the CLI agent to drive scans. This view refreshes on reload.</p>
    </body>
    </html>
    """
    return html

if __name__ == "__main__":
    print("PrisimRedline GUI → http://127.0.0.1:8088")
    uvicorn.run(app, host="127.0.0.1", port=8088)
