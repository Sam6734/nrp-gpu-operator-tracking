"""
gpu-tracking web UI: Flask dashboard backed by PostgreSQL.
Receives events from the snr-netbox-watcher operator and gpu-power-agent,
stores them, and serves a human-readable dashboard.
"""
import os
import time
import logging
import threading
import psycopg2
import psycopg2.extras
from flask import Flask, jsonify, render_template, request, abort

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("web-ui")

app = Flask(__name__)

DB_HOST     = os.environ.get("DB_HOST", "postgresql")
DB_PORT     = int(os.environ.get("DB_PORT", "5432"))
DB_NAME     = os.environ.get("DB_NAME", "gputrack")
DB_USER     = os.environ.get("DB_USER", "gputrack")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

# Retention: how many days to keep each event type. Set to 0 to disable.
REBOOT_EVENTS_RETENTION_DAYS   = int(os.environ.get("REBOOT_EVENTS_RETENTION_DAYS",   "90"))
POWER_EVENTS_RETENTION_DAYS    = int(os.environ.get("POWER_EVENTS_RETENTION_DAYS",    "30"))
OPERATOR_EVENTS_RETENTION_DAYS = int(os.environ.get("OPERATOR_EVENTS_RETENTION_DAYS", "90"))
CLEANUP_INTERVAL_SEC           = int(os.environ.get("CLEANUP_INTERVAL_SEC",           "86400"))


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
                -- Node registry: every node that has ever reported, persists across pod restarts.
                -- Upserted on every power-limit and reboot event so the node list never disappears.
                CREATE TABLE IF NOT EXISTS node_registry (
                    node_name   TEXT        PRIMARY KEY,
                    gpu_model   TEXT,
                    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                -- Node inventory: expected GPU count synced from NetBox by the operator on startup.
                -- Never updated automatically — operator syncs once on pod start.
                CREATE TABLE IF NOT EXISTS node_inventory (
                    node_name           TEXT        PRIMARY KEY,
                    netbox_device_id    INTEGER,
                    expected_gpu_count  INTEGER,
                    expected_gpu_model  TEXT,
                    last_synced         TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS reboot_events (
                    id                SERIAL PRIMARY KEY,
                    node_name         TEXT        NOT NULL,
                    boot_id           TEXT,
                    gpu_model         TEXT,
                    reboot_count_24h  INTEGER     DEFAULT 0,
                    power_pct_applied INTEGER,
                    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
                    id                    SERIAL PRIMARY KEY,
                    node_name             TEXT        NOT NULL,
                    gpu_index             INTEGER,
                    gpu_model             TEXT,
                    old_power_limit_watts INTEGER,
                    new_power_limit_watts INTEGER,
                    target_pct            INTEGER,
                    status                TEXT        DEFAULT 'pending',
                    applied_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_pl_node ON power_limit_events(node_name);
                CREATE INDEX IF NOT EXISTS idx_pl_ts   ON power_limit_events(applied_at DESC);
            """)
            # Live migration: add k8s_allocatable_gpu_count if not yet present
            cur.execute("""
                ALTER TABLE node_registry
                    ADD COLUMN IF NOT EXISTS k8s_allocatable_gpu_count INTEGER;
            """)
        conn.commit()
    log.info("Database schema initialised.")
    # Start retention cleanup thread (runs once immediately then every 24 h)
    threading.Thread(target=_run_cleanup, name="retention-cleanup", daemon=True).start()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _upsert_node_registry(cur, node_name: str, gpu_model: str = None):
    """Keep node_registry up to date so nodes persist even without recent events."""
    cur.execute("""
        INSERT INTO node_registry (node_name, gpu_model, first_seen, last_seen)
        VALUES (%s, %s, NOW(), NOW())
        ON CONFLICT (node_name) DO UPDATE SET
            gpu_model = COALESCE(EXCLUDED.gpu_model, node_registry.gpu_model),
            last_seen = NOW()
    """, (node_name, gpu_model or None))


# ── API endpoints (called by operator + power agent) ──────────────────────────

@app.post("/api/events/reboot")
def api_reboot_event():
    data = request.get_json(silent=True) or {}
    node_name = data.get("node_name", "")
    if not node_name:
        abort(400, "node_name required")
    with get_db() as conn:
        with conn.cursor() as cur:
            _upsert_node_registry(cur, node_name, data.get("gpu_model"))
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
            _upsert_node_registry(cur, node_name, data.get("gpu_model"))
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


@app.post("/api/nodes/sync-netbox")
def api_sync_netbox():
    """Called by the operator on startup to record expected GPU counts from NetBox."""
    data = request.get_json(silent=True) or {}
    node_name = data.get("node_name", "")
    if not node_name:
        abort(400, "node_name required")
    expected = data.get("expected_gpu_count")
    if expected is None:
        abort(400, "expected_gpu_count required")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO node_inventory
                    (node_name, netbox_device_id, expected_gpu_count, expected_gpu_model, last_synced)
                VALUES (%s, %s, %s, %s, NOW())
                ON CONFLICT (node_name) DO UPDATE SET
                    netbox_device_id   = COALESCE(EXCLUDED.netbox_device_id,   node_inventory.netbox_device_id),
                    expected_gpu_count = EXCLUDED.expected_gpu_count,
                    expected_gpu_model = COALESCE(EXCLUDED.expected_gpu_model, node_inventory.expected_gpu_model),
                    last_synced        = NOW()
            """, (
                node_name,
                data.get("netbox_device_id"),
                expected,
                data.get("expected_gpu_model"),
            ))
        conn.commit()
    return jsonify({"ok": True}), 201


@app.post("/api/nodes/k8s-counts")
def api_update_k8s_counts():
    """Batch-update k8s allocatable GPU counts. Called by operator every 10 min."""
    data = request.get_json(silent=True) or {}
    nodes = data.get("nodes", [])
    if not nodes:
        abort(400, "nodes list required")
    updated = 0
    with get_db() as conn:
        with conn.cursor() as cur:
            for entry in nodes:
                node_name = (entry.get("node_name") or "").strip()
                k8s_count = entry.get("k8s_gpu_count")
                if not node_name:
                    continue
                cur.execute("""
                    INSERT INTO node_registry (node_name, first_seen, last_seen, k8s_allocatable_gpu_count)
                    VALUES (%s, NOW(), NOW(), %s)
                    ON CONFLICT (node_name) DO UPDATE SET
                        k8s_allocatable_gpu_count = EXCLUDED.k8s_allocatable_gpu_count,
                        last_seen = NOW()
                """, (node_name, k8s_count))
                updated += 1
        conn.commit()
    return jsonify({"ok": True, "updated": updated})


# ── JSON API (used by dashboard JS) ──────────────────────────────────────────

@app.get("/api/nodes")
def api_nodes():
    """Per-node summary. Uses node_registry as base so all nodes persist across restarts."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                WITH reboot_stats AS (
                    SELECT
                        node_name,
                        MAX(gpu_model)                                              AS gpu_model,
                        COUNT(*)                                                    AS total_reboots,
                        SUM(CASE WHEN created_at > NOW() - INTERVAL '24h'
                                 THEN 1 ELSE 0 END)                                AS reboots_24h,
                        MAX(created_at)                                             AS last_reboot
                    FROM reboot_events
                    GROUP BY node_name
                ),
                latest_power AS (
                    SELECT DISTINCT ON (node_name)
                        node_name,
                        new_power_limit_watts   AS current_power_w,
                        target_pct              AS current_pct,
                        applied_at              AS power_updated_at
                    FROM power_limit_events
                    ORDER BY node_name, applied_at DESC
                ),
                actual_gpu_counts AS (
                    -- Count distinct GPU indices seen in the most recent nvidia-smi batch
                    -- (all events within 10 min of the latest event for that node)
                    SELECT
                        p.node_name,
                        COUNT(DISTINCT p.gpu_index) AS actual_gpu_count,
                        MAX(p.gpu_model)            AS power_gpu_model
                    FROM power_limit_events p
                    INNER JOIN (
                        SELECT node_name, MAX(applied_at) AS max_at
                        FROM   power_limit_events
                        GROUP  BY node_name
                    ) latest ON p.node_name = latest.node_name
                           AND p.applied_at >= latest.max_at - INTERVAL '10 minutes'
                    GROUP BY p.node_name
                )
                SELECT
                    nr.node_name,
                    COALESCE(r.gpu_model, a.power_gpu_model, nr.gpu_model) AS gpu_model,
                    COALESCE(r.total_reboots, 0)                           AS total_reboots,
                    COALESCE(r.reboots_24h,  0)                            AS reboots_24h,
                    r.last_reboot,
                    p.current_power_w,
                    p.current_pct,
                    p.power_updated_at,
                    a.actual_gpu_count,
                    nr.k8s_allocatable_gpu_count,
                    i.expected_gpu_count,
                    i.expected_gpu_model,
                    i.last_synced       AS inventory_synced_at,
                    i.netbox_device_id,
                    nr.first_seen,
                    nr.last_seen
                FROM node_registry nr
                LEFT JOIN reboot_stats     r ON r.node_name = nr.node_name
                LEFT JOIN latest_power     p ON p.node_name = nr.node_name
                LEFT JOIN actual_gpu_counts a ON a.node_name = nr.node_name
                LEFT JOIN node_inventory   i ON i.node_name = nr.node_name
                ORDER BY COALESCE(r.last_reboot, p.power_updated_at, nr.last_seen) DESC NULLS LAST
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
                    "SELECT * FROM reboot_events ORDER BY created_at DESC LIMIT %s", (limit,),
                )
            reboots = cur.fetchall()

            if node:
                cur.execute(
                    "SELECT * FROM power_limit_events WHERE node_name=%s ORDER BY applied_at DESC LIMIT %s",
                    (node, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM power_limit_events ORDER BY applied_at DESC LIMIT %s", (limit,),
                )
            power = cur.fetchall()

    return jsonify({
        "reboot_events":      [dict(r) for r in reboots],
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
    limit    = min(int(request.args.get("limit", 200)), 1000)
    node     = request.args.get("node")
    severity = request.args.get("severity")
    with get_db() as conn:
        with conn.cursor() as cur:
            filters, params = [], []
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

@app.get("/api/gpu-inventory")
def api_gpu_inventory():
    """Fleet-wide GPU inventory: k8s allocatable vs expected GPU counts for all nodes.
    k8s_allocatable_gpu_count is the authoritative actual count (from device plugin)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    nr.node_name,
                    nr.gpu_model,
                    nr.k8s_allocatable_gpu_count,
                    i.expected_gpu_count,
                    i.expected_gpu_model,
                    i.netbox_device_id,
                    i.last_synced   AS inventory_synced_at,
                    nr.last_seen,
                    CASE
                        WHEN i.expected_gpu_count IS NULL OR nr.k8s_allocatable_gpu_count IS NULL THEN 'unknown'
                        WHEN nr.k8s_allocatable_gpu_count < i.expected_gpu_count                  THEN 'missing'
                        ELSE 'ok'
                    END AS gpu_status
                FROM node_registry nr
                LEFT JOIN node_inventory i ON i.node_name = nr.node_name
                ORDER BY
                    CASE
                        WHEN i.expected_gpu_count IS NULL OR nr.k8s_allocatable_gpu_count IS NULL THEN 2
                        WHEN nr.k8s_allocatable_gpu_count < i.expected_gpu_count                  THEN 0
                        ELSE 1
                    END,
                    nr.node_name
            """)
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/inventory")
def inventory():
    return render_template("inventory.html")


# ── Retention cleanup ─────────────────────────────────────────────────────────

def _run_cleanup():
    """Delete old event rows based on retention settings. Runs once on startup
    then every CLEANUP_INTERVAL_SEC (default 24 h)."""
    while True:
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    totals = {}

                    if REBOOT_EVENTS_RETENTION_DAYS > 0:
                        cur.execute(
                            "DELETE FROM reboot_events WHERE created_at < NOW() - INTERVAL '%s days'",
                            (REBOOT_EVENTS_RETENTION_DAYS,),
                        )
                        totals["reboot_events"] = cur.rowcount

                    if POWER_EVENTS_RETENTION_DAYS > 0:
                        cur.execute(
                            "DELETE FROM power_limit_events WHERE applied_at < NOW() - INTERVAL '%s days'",
                            (POWER_EVENTS_RETENTION_DAYS,),
                        )
                        totals["power_limit_events"] = cur.rowcount

                    if OPERATOR_EVENTS_RETENTION_DAYS > 0:
                        cur.execute(
                            "DELETE FROM operator_events WHERE created_at < NOW() - INTERVAL '%s days'",
                            (OPERATOR_EVENTS_RETENTION_DAYS,),
                        )
                        totals["operator_events"] = cur.rowcount

                conn.commit()

            deleted = {k: v for k, v in totals.items() if v > 0}
            if deleted:
                log.info(f"Retention cleanup deleted: {deleted}")
            else:
                log.info("Retention cleanup: nothing to delete")

        except Exception as e:
            log.warning(f"Retention cleanup failed: {e}")

        time.sleep(CLEANUP_INTERVAL_SEC)


if __name__ == "__main__":
    init_db()
    threading.Thread(target=_run_cleanup, name="retention-cleanup", daemon=True).start()
    app.run(host="0.0.0.0", port=8080, debug=False)
