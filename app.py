"""API Contract Forge - Flask application.

Local-first API contract reviewer. No API keys, no outbound network calls.
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3

from flask import Flask, Response, jsonify, render_template, request

from engine import PROFILES, analyze, parse_contract, render_markdown, to_yaml
from samples import SAMPLE_BY_ID, SAMPLES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "apicf.db")
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "created_at TEXT NOT NULL,"
            "title TEXT, mode TEXT, profile TEXT, score REAL, verdict TEXT,"
            "source TEXT, report TEXT, notes TEXT, rating INTEGER)"
        )
        conn.commit()


init_db()


def save_session(report: dict, source: str) -> int:
    created = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO sessions (created_at, title, mode, profile, score, verdict,"
            " source, report) VALUES (?,?,?,?,?,?,?,?)",
            (created, report.get("title", ""), report.get("mode", ""),
             report.get("profile", ""), report.get("score", 0),
             report.get("verdict", ""), source, json.dumps(report)),
        )
        conn.commit()
        return int(cur.lastrowid)


def row_to_session(row: sqlite3.Row) -> dict:
    report = json.loads(row["report"]) if row["report"] else {}
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "title": row["title"],
        "mode": row["mode"],
        "profile": row["profile"],
        "score": row["score"],
        "verdict": row["verdict"],
        "notes": row["notes"] or "",
        "rating": row["rating"],
        "report": report,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({"ok": True, "app": "api-contract-forge", "version": "1.0.0"})


@app.route("/api/profiles")
def profiles():
    return jsonify({"profiles": [{"id": k, "label": v["label"], "weights": v["weights"]}
                                 for k, v in PROFILES.items()]})


@app.route("/api/samples")
def samples():
    return jsonify({"samples": [
        {"id": s["id"], "title": s["title"], "description": s["description"],
         "mode": s["mode"], "preview": s["content"][:280]}
        for s in SAMPLES]})


@app.route("/api/sample/<sample_id>")
def sample(sample_id: str):
    item = SAMPLE_BY_ID.get(sample_id)
    if not item:
        return jsonify({"error": "unknown sample"}), 404
    return jsonify(item)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    raw = data.get("input") or data.get("text") or ""
    mode = data.get("mode") or "auto"
    profile = data.get("profile") or "rest"
    if not str(raw).strip():
        return jsonify({"error": "Paste a contract brief or an OpenAPI document first."}), 400
    try:
        model = parse_contract(str(raw), mode)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not model["endpoints"]:
        return jsonify({"error": "No HTTP endpoints found. Write lines like "
                                 "'GET /v1/orders' or paste an OpenAPI document."}), 400
    report = analyze(model, profile)
    report["session_id"] = save_session(report, str(raw))
    return jsonify(report)


@app.route("/api/sessions")
def api_sessions():
    with db() as conn:
        rows = conn.execute(
            "SELECT id, created_at, title, mode, profile, score, verdict, notes, rating"
            " FROM sessions ORDER BY id DESC LIMIT 60").fetchall()
    return jsonify({"sessions": [dict(r) for r in rows]})


@app.route("/api/sessions/<int:sid>")
def api_session(sid: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (sid,)).fetchone()
    if not row:
        return jsonify({"error": "session not found"}), 404
    return jsonify(row_to_session(row))


@app.route("/api/sessions/<int:sid>", methods=["PATCH"])
def api_patch_session(sid: int):
    data = request.get_json(silent=True) or {}
    with db() as conn:
        row = conn.execute("SELECT id FROM sessions WHERE id = ?", (sid,)).fetchone()
        if not row:
            return jsonify({"error": "session not found"}), 404
        if "notes" in data:
            conn.execute("UPDATE sessions SET notes = ? WHERE id = ?",
                         (str(data["notes"] or "")[:4000], sid))
        if "rating" in data:
            try:
                rating = int(data["rating"])
            except (TypeError, ValueError):
                rating = None
            if rating is not None and 1 <= rating <= 5:
                conn.execute("UPDATE sessions SET rating = ? WHERE id = ?", (rating, sid))
        conn.commit()
    return api_session(sid)


@app.route("/api/export/<int:sid>")
def api_export(sid: int):
    fmt = (request.args.get("fmt") or "md").lower()
    with db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (sid,)).fetchone()
    if not row:
        return jsonify({"error": "session not found"}), 404
    report = json.loads(row["report"]) if row["report"] else {}
    name = (report.get("title") or "api-contract").lower()
    name = "".join(ch if ch.isalnum() else "-" for ch in name).strip("-")[:48] or "api-contract"
    if fmt == "json":
        body = json.dumps(report, indent=2)
        mime = "application/json"
        ext = "json"
    elif fmt == "yaml":
        body = to_yaml(report.get("openapi") or {})
        mime = "text/yaml"
        ext = "openapi.yaml"
    else:
        body = render_markdown(report)
        mime = "text/markdown"
        ext = "md"
    return Response(body, mimetype=mime, headers={
        "Content-Disposition": 'attachment; filename="%s-review.%s"' % (name, ext)})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8765, debug=False)
