"""
gpu-tracking web UI: Flask dashboard backed by PostgreSQL.
Receives events from the snr-netbox-watcher operator and gpu-power-agent,
stores them, and serves a human-readable dashboard.
"""
import os
import logging
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template, request, abort

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("web-ui")

app = Flask(__name__)

DB_HOST = os.environ.get("DB_HOST", "postgresql")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "gputrack")
DB_USER = os.environ.get("DB_USER", "gputrack")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")


def get_db():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
        connect_timeout=5,
    )


def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reboot_events (
                    id          SERIAL PRIMARY KEY,
                    node_name   TEXT        NOT NULL,
                    boot_id     TEXT,
                    gpu_model   TEXT,
                    reboot_count_24h  INTEGER DEFAULT 0,
                    power_pct_applied INTEGER,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_reboot_node ON reboot_events(node_name);
                CREATE INDEX IF NOT EXISTS idx_reboot_ts   ON reboot_events(created_at DESC);

                CREATE TABLE IF NOT EXISTS operator_events (
                    id          SERIAL PRIMARY KEY,
                    node_name   TEXT        NOT NULL,
                    event_type  TEXT        NOT NULL,
                    severity    TEXT        NOT NULL DEFAULT 'info',
                    message     TEXT,
                    metadata    JSONB,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_oe_node ON operator_events(node_name);
                CREATE INDEX IF NOT EXISTS idx_oe_ts   ON operator_events(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_oe_type ON operator_events(event_type);

                CREATE TABLE IF NOT EXISTS power_limit_events (
                    id                   SERIAL PRIMARY KEY,
                    node_name            TEXT        NOT NULL,
                    gpu_index            INTEGER,
                    gpu_model            TEXT,
                    old_power_limit_watts INTEGER,
                    new_power_limit_watts INTEGER,
                    target_pct           INTEGER,
                    status               TEXT DEFAULT 'pending',
                    applied_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_pl_node ON power_limit_events(node_name);
                CREATE INDEX IF NOT EXISTS idx_pl_ts   ON power_limit_events(applied_at DESC);
            """)
        conn.commit()
    log.info("Database schema initialised.")


# ── API endpoints (called by operator + power agent) ──────────────────────────

@app.post("/api/events/reboot")
def api_reboot_event():
    data = request.get_json(silent=True) or {}
    node_name = data.get("node_name", "")
    if not node_name:
        abort(400, "node_name required")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO reboot_events
                   (node_name, boot_id, gpu_model, reboot_count_24h, power_pct_applied)
                   VALUES (%s, %s, %s, %s, %s)""",
                (
                    node_name,
                    data.get("boot_id"),
                    data.get("gpu_model"),
                    data.get("reboot_count_24h", 0),
                    data.get("power_pct_applied"),
                ),
            )
        conn.commit()
    return jsonify({"ok": True}), 201


@app.post("/api/events/power-limit")
def api_power_limit_event():
    data = request.get_json(silent=True) or {}
    node_name = data.get("node_name", "")
    if not node_name:
        abort(400, "node_name required")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO power_limit_events
                   (node_name, gpu_index, gpu_model, old_power_limit_watts,
                    new_power_limit_watts, target_pct, status)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (
                    node_name,
                    data.get("gpu_index"),
                    data.get("gpu_model"),
                    data.get("old_power_limit_watts"),
                    data.get("new_power_limit_watts"),
                    data.get("target_pct"),
                    data.get("status", "applied"),
                ),
            )
        conn.commit()
    return jsonify({"ok": True}), 201


# ── JSON API (used by dashboard JS) ──────────────────────────────────────────

@app.get("/api/nodes")
def api_nodes():
    """Per-node summary: last seen GPU model, latest power limit, reboot count (24h)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    r.node_name,
                    MAX(r.gpu_model)                                    AS gpu_model,
                    COUNT(*)                                            AS total_reboots,
                    SUM(CASE WHEN r.created_at > NOW() - INTERVAL '24h'
                             THEN 1 ELSE 0 END)                        AS reboots_24h,
                    MAX(r.created_at)                                   AS last_reboot,
                    (SELECT p.new_power_limit_watts
                     FROM   power_limit_events p
                     WHERE  p.node_name = r.node_name
                     ORDER  BY p.applied_at DESC LIMIT 1)              AS current_power_w,
                    (SELECT p.target_pct
                     FROM   power_limit_events p
                     WHERE  p.node_name = r.node_name
                     ORDER  BY p.applied_at DESC LIMIT 1)              AS current_pct
                FROM reboot_events r
                GROUP BY r.node_name
                ORDER BY last_reboot DESC
            """)
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/events")
def api_events():
    limit = min(int(request.args.get("limit", 200)), 1000)
    node  = request.args.get("node")
    with get_db() as conn:
        with conn.cursor() as cur:
            if node:
                cur.execute(
                    "SELECT * FROM reboot_events WHERE node_name=%s ORDER BY created_at DESC LIMIT %s",
                    (node, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM reboot_events ORDER BY created_at DESC LIMIT %s",
                    (limit,),
                )
            reboots = cur.fetchall()

            if node:
                cur.execute(
                    "SELECT * FROM power_limit_events WHERE node_name=%s ORDER BY applied_at DESC LIMIT %s",
                    (node, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM power_limit_events ORDER BY applied_at DESC LIMIT %s",
                    (limit,),
                )
            power = cur.fetchall()

    return jsonify({
        "reboot_events": [dict(r) for r in reboots],
        "power_limit_events": [dict(p) for p in power],
    })


@app.post("/api/events/operator-log")
def api_operator_log():
    data = request.get_json(silent=True) or {}
    node_name = data.get("node_name", "")
    if not node_name:
        abort(400, "node_name required")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO operator_events
                   (node_name, event_type, severity, message, metadata)
                   VALUES (%s, %s, %s, %s, %s)""",
                (
                    node_name,
                    data.get("event_type", "unknown"),
                    data.get("severity", "info"),
                    data.get("message"),
                    psycopg2.extras.Json(data.get("metadata") or {}),
                ),
            )
        conn.commit()
    return jsonify({"ok": True}), 201


@app.get("/api/events/operator-log")
def api_get_operator_log():
    limit = min(int(request.args.get("limit", 200)), 1000)
    node  = request.args.get("node")
    severity = request.args.get("severity")  # filter: warning, critical
    with get_db() as conn:
        with conn.cursor() as cur:
            filters = []
            params  = []
            if node:
                filters.append("node_name = %s"); params.append(node)
            if severity:
                filters.append("severity = %s"); params.append(severity)
            where = ("WHERE " + " AND ".join(filters)) if filters else ""
            params.append(limit)
            cur.execute(
                f"SELECT * FROM operator_events {where} ORDER BY created_at DESC LIMIT %s",
                params,
            )
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/healthz")
def healthz():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 503


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=False)
