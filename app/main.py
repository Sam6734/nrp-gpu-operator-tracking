import os
import re
import time
import hashlib
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any, List, Set

import requests
import kopf
import kubernetes
from kubernetes import client as k8s
from prometheus_client import Counter, start_http_server

# -------------------- Env / Config --------------------
NB_URL = os.environ.get("NB_URL", "").rstrip("/")
NB_TOKEN = os.environ.get("NB_TOKEN", "")
NB_OBJECT_TYPE = os.environ.get("NB_OBJECT_TYPE", "dcim.device")  # dcim.device | virtualization.virtualmachine

PROM_URL = os.environ.get("PROM_URL", "").rstrip("/")  # optional
GPUFAILED_RECENT_WINDOW = os.environ.get("GPUFAILED_RECENT_WINDOW", "1h")

METRICS_PORT = int(os.environ.get("METRICS_PORT", "8000"))

SNR_NAMESPACE = os.environ.get("SNR_NAMESPACE", "operators")
SNR_SWEEP_PERIOD_SEC = int(os.environ.get("SNR_SWEEP_PERIOD_SEC", "180"))

ENABLE_ACTIVE_REMEDIATION = os.environ.get("ENABLE_ACTIVE_REMEDIATION", "false").lower() == "true"
STUCK_GRACE_MIN = int(os.environ.get("STUCK_GRACE_MINUTES", "30"))
STUCK_DELETE_AFTER_MIN = int(os.environ.get("STUCK_DELETE_AFTER_MINUTES", "45"))

LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "24"))

TAINT_SKIP_LIST = os.environ.get(
    "TAINT_SKIP_LIST",
    "nautilus.io/issue,nautilus.io/system,nautilus.io/ceph,nautilus.io/ceph-external",
)
TAINT_SKIP_KEYS = {k.strip() for k in TAINT_SKIP_LIST.split(",") if k.strip()}

NETBOX_TIMEOUT_SEC = int(os.environ.get("NETBOX_TIMEOUT_SEC", "20"))
SKIP_LOG_EVERY_SEC = int(os.environ.get("SKIP_LOG_EVERY_SEC", "1800"))
BLOCKED_LOG_EVERY_SEC = int(os.environ.get("BLOCKED_LOG_EVERY_SEC", "21600"))

JOURNAL_MAX_MSG_CHARS = int(os.environ.get("JOURNAL_MAX_MSG_CHARS", "160"))

LOCAL_FP_TTL_SEC = int(os.environ.get("LOCAL_FP_TTL_SEC", "300"))
NETBOX_RETENTION_DAYS = int(os.environ.get("NETBOX_RETENTION_DAYS", "30"))
NETBOX_CLEANUP_EVERY_SEC = int(os.environ.get("NETBOX_CLEANUP_EVERY_SEC", "86400"))
KOPF_OBJECTS_LOG_LEVEL = os.environ.get("KOPF_OBJECTS_LOG_LEVEL", "WARNING").upper()

# -------------------- GPU Power Management Config --------------------
GPU_STORM_THRESHOLD = int(os.environ.get("GPU_STORM_THRESHOLD", "3"))
GPU_POWER_LIMIT_PCT_STORM = int(os.environ.get("GPU_POWER_LIMIT_PCT_STORM", "80"))
GPU_POWER_LIMIT_PCT_NORMAL = int(os.environ.get("GPU_POWER_LIMIT_PCT_NORMAL", "100"))
WEB_UI_URL = os.environ.get("WEB_UI_URL", "").rstrip("/")

# In-memory dedup for non-gpufailed reboots logged to web UI (avoids re-posting on every sweep).
# Lost on operator restart, which is acceptable — worst case: one duplicate entry.
_webui_reboot_boot_ids_sent: set = set()

UNREACHABLE_TAINT_KEYS = {
    "node.kubernetes.io/unreachable",
    "node.kubernetes.io/not-ready",
}

TAG_GPUFAILED_INCIDENT = "GPUFAILED-INCIDENT"
TAG_REBOOT_CONFIRMED = "SNR-REBOOT-CONFIRMED"
TAG_STUCK_DELETED = "SNR-STUCK-DELETED"
TAG_AUTO_DELETE_BLOCKED = "SNR-AUTO-DELETE-BLOCKED"

OPERATOR_TAGS: Set[str] = {
    TAG_GPUFAILED_INCIDENT,
    TAG_REBOOT_CONFIRMED,
    TAG_STUCK_DELETED,
    TAG_AUTO_DELETE_BLOCKED,
}

if not NB_URL or not NB_TOKEN:
    raise RuntimeError("NB_URL and NB_TOKEN are required.")

# -------------------- HTTP Sessions --------------------
_NB = requests.Session()
_NB.headers.update({"Authorization": f"Token {NB_TOKEN}", "Content-Type": "application/json"})

_PROM = requests.Session()

# -------------------- Metrics --------------------
SNR_EVENTS = Counter(
    "snr_events_total",
    "Count of SelfNodeRemediation events we handled",
    ["node", "action"],
)

SNR_STUCK_DELETES = Counter(
    "snr_watcher_stuck_deletes_total",
    "Count of stuck SNR CR deletions",
    ["node"],
)

SNR_AUTO_DELETE_BLOCKS = Counter(
    "snr_auto_delete_blocked_total",
    "Count of SNR CR deletions blocked after repeated failed unsticks",
    ["node"],
)

NETBOX_LOOKUPS = Counter(
    "snr_netbox_lookups_total",
    "Count of NetBox object lookups",
    ["result"],
)

NETBOX_JOURNAL_POSTS = Counter(
    "snr_netbox_journal_posts_total",
    "Count of NetBox journal post attempts",
    ["result"],
)

NETBOX_JOURNAL_DELETES = Counter(
    "snr_netbox_journal_deletes_total",
    "Count of NetBox journal entry deletions",
    ["result"],
)

NETBOX_CLEANUPS = Counter(
    "snr_netbox_cleanup_total",
    "Count of NetBox journal cleanup runs",
    ["result"],
)

PROM_QUERIES = Counter(
    "snr_prom_queries_total",
    "Count of Prometheus instant queries",
    ["result"],
)

GPU_POWER_ANNOTATIONS = Counter(
    "snr_gpu_power_annotations_total",
    "Count of GPU power limit annotations applied to nodes after reboot",
    ["node", "pct"],
)

# -------------------- In-memory caches --------------------
_LOG_LAST: Dict[str, float] = {}
_DEVICE_ID_CACHE: Dict[str, Tuple[Optional[int], float]] = {}
_DEVICE_ID_CACHE_TTL_SEC = 300

_LOCAL_FP_CACHE: Dict[str, float] = {}
_NETBOX_CLEANUP_LAST: Dict[int, float] = {}

_SWEEP_THREAD_STARTED = False
_SWEEP_THREAD_LOCK = threading.Lock()

# -------------------- Helpers --------------------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _parse_rfc3339(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

def _fmt_ts(ts) -> str:
    if not ts:
        return ""

    if isinstance(ts, datetime):
        try:
            return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return ts.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return str(ts)

    s = str(ts)
    dt = _parse_rfc3339(s)
    if not dt:
        return s.strip().replace(" ", "T")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def _squash_ws(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def _truncate(s: str, n: int) -> str:
    s = s or ""
    if n <= 0:
        return ""
    if len(s) <= n:
        return s
    return s[: max(0, n - 1)] + "…"

def _extract_human_msg(msg: str) -> str:
    if not msg:
        return ""
    m = _squash_ws(msg)

    m2 = re.search(r"\bXid\b.*?:\s*\d+\s*,\s*(.*)$", m, re.IGNORECASE)
    if m2:
        m = m2.group(1).strip()

    m = re.sub(r"^(NVRM:\s*)", "", m, flags=re.IGNORECASE).strip()
    return _truncate(m, JOURNAL_MAX_MSG_CHARS)

def _resp_text(resp: Optional[requests.Response], limit: int = 500) -> str:
    if resp is None:
        return ""
    try:
        return (resp.text or "")[:limit]
    except Exception:
        return ""

def _is_operator_comment(comment: str) -> bool:
    if not comment:
        return False
    c = comment.lower()
    return any(tag.lower() in c for tag in OPERATOR_TAGS)

def _purge_expired_local_fp_cache() -> None:
    now = time.time()
    expired = [fp for fp, ts in _LOCAL_FP_CACHE.items() if now - ts >= LOCAL_FP_TTL_SEC]
    for fp in expired:
        _LOCAL_FP_CACHE.pop(fp, None)

def _reserve_local_fingerprint(fingerprint: str) -> bool:
    _purge_expired_local_fp_cache()
    now = time.time()
    ts = _LOCAL_FP_CACHE.get(fingerprint)
    if ts is not None and now - ts < LOCAL_FP_TTL_SEC:
        return False
    _LOCAL_FP_CACHE[fingerprint] = now
    return True

def _release_local_fingerprint(fingerprint: str) -> None:
    _LOCAL_FP_CACHE.pop(fingerprint, None)

# -------------------- Prom helpers (optional) --------------------
def _prom_query_instant(promql: str, logger=None) -> list:
    if not PROM_URL:
        if logger:
            logger.debug("PROM_URL not set; skipping Prometheus query.")
        PROM_QUERIES.labels(result="disabled").inc()
        return []

    resp = None
    try:
        resp = _PROM.get(
            f"{PROM_URL}/api/v1/query",
            params={"query": promql},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("result", [])
        PROM_QUERIES.labels(result="success").inc()
        return data
    except Exception as e:
        PROM_QUERIES.labels(result="error").inc()
        if logger:
            logger.warning(
                f"Prometheus query failed: {e}; promql={promql}; response={_resp_text(resp)}"
            )
        return []

def _gpufailed_true_recently(node_name: str, logger=None) -> bool:
    q = (
        f'max_over_time('
        f'kube_node_status_condition{{condition="GPUFailed",status="true",node="{node_name}"}}'
        f'[{GPUFAILED_RECENT_WINDOW}])'
    )
    data = _prom_query_instant(q, logger=logger)
    if not data:
        return False
    try:
        val = float(data[0].get("value", [None, "0"])[1])
        return val >= 1.0
    except Exception as e:
        if logger:
            logger.warning(f"{node_name}: failed to parse Prometheus GPUFailed query result: {e}")
        return False

# -------------------- Node helpers --------------------
def _node_has_any_taint_key(node: k8s.V1Node, keys: set) -> bool:
    if not node or not node.spec or not node.spec.taints:
        return False
    for t in node.spec.taints:
        if t.key in keys:
            return True
    return False

def _node_unreachable_or_notready(node: k8s.V1Node) -> bool:
    if _node_has_any_taint_key(node, UNREACHABLE_TAINT_KEYS):
        return True

    if not node or not node.status or not node.status.conditions:
        return True

    for c in node.status.conditions:
        if c.type == "Ready":
            return c.status != "True"
    return True

def _node_unschedulable(node: k8s.V1Node) -> bool:
    try:
        return bool(getattr(node.spec, "unschedulable", False))
    except Exception:
        return False

def _matching_skip_taints(node: k8s.V1Node) -> List[str]:
    out = []
    if not node or not node.spec or not node.spec.taints:
        return out
    for t in node.spec.taints:
        if t.key in TAINT_SKIP_KEYS:
            out.append(t.key)
    return sorted(out)

def _get_node_boot_id(node_obj: k8s.V1Node) -> Optional[str]:
    try:
        ni = getattr(node_obj.status, "node_info", None)
        if not ni:
            return None
        return getattr(ni, "boot_id", None)
    except Exception:
        return None

def _get_gpufailed_condition(node_obj: k8s.V1Node) -> Optional[Dict[str, Any]]:
    if not node_obj or not node_obj.status or not node_obj.status.conditions:
        return None
    for c in node_obj.status.conditions:
        if c.type == "GPUFailed" and getattr(c, "status", None) == "True":
            return {
                "reason": getattr(c, "reason", "") or "",
                "message": getattr(c, "message", "") or "",
                "lastTransitionTime": getattr(c, "last_transition_time", None)
                or getattr(c, "lastTransitionTime", None)
                or "",
            }
    return None

_PCI_RE = re.compile(r"PCI:([0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}(?:\.[0-9a-fA-F])?)")
_XID_RE = re.compile(r"\bXid\b.*?:\s*(\d+)\b", re.IGNORECASE)
_SUFFIX_RE = re.compile(r"-[a-z0-9]{5}$")

def _extract_gpu_ids_from_message(msg: str) -> Tuple[Optional[str], Optional[str]]:
    if not msg:
        return (None, None)
    pci = None
    xid = None
    m = _PCI_RE.search(msg)
    if m:
        pci = m.group(1)
    m2 = _XID_RE.search(msg)
    if m2:
        xid = m2.group(1)
    return (pci, xid)

def _incident_fingerprint(node_name: str, cond: Dict[str, Any]) -> str:
    ltt = cond.get("lastTransitionTime", "")
    return _sha1(
        f"{node_name}|GPUFailed|{str(ltt)}|{cond.get('reason','')}|{cond.get('message','')}"
    )

# -------------------- Node resolution --------------------
def _strip_cr_suffix(name: str) -> str:
    return _SUFFIX_RE.sub("", name)

def _resolve_node_name_from_cr(cr_name: str, body: Dict[str, Any], logger=None) -> Optional[str]:
    core = k8s.CoreV1Api()

    try:
        core.read_node(name=cr_name)
        if logger:
            logger.debug(f"{cr_name}: resolved backing Node by exact CR name match.")
        return cr_name
    except Exception:
        pass

    base = _strip_cr_suffix(cr_name)
    if base != cr_name:
        try:
            core.read_node(name=base)
            if logger:
                logger.debug(f"{cr_name}: resolved backing Node by stripped suffix -> {base}.")
            return base
        except Exception:
            pass

    spec_node = body.get("spec", {}).get("nodeName") or body.get("status", {}).get("nodeName")
    if spec_node:
        try:
            core.read_node(name=spec_node)
            if logger:
                logger.debug(f"{cr_name}: resolved backing Node from spec/status nodeName -> {spec_node}.")
            return spec_node
        except Exception:
            if logger:
                logger.warning(f"{cr_name}: spec/status nodeName={spec_node} did not resolve to a Node.")

    try:
        for n in core.list_node().items:
            if n.metadata and n.metadata.labels:
                hn = n.metadata.labels.get("kubernetes.io/hostname") or ""
                if hn == base:
                    if logger:
                        logger.debug(
                            f"{cr_name}: resolved backing Node by kubernetes.io/hostname={base} -> {n.metadata.name}."
                        )
                    return n.metadata.name
    except Exception as e:
        if logger:
            logger.warning(f"{cr_name}: failed while scanning Nodes for hostname match: {e}")

    return None

# -------------------- NetBox helpers --------------------
def _netbox_object_lookup_url() -> Optional[str]:
    if NB_OBJECT_TYPE == "dcim.device":
        return f"{NB_URL}/api/dcim/devices/"
    if NB_OBJECT_TYPE == "virtualization.virtualmachine":
        return f"{NB_URL}/api/virtualization/virtual-machines/"
    return None

def _assigned_object_type() -> str:
    return NB_OBJECT_TYPE

def _device_id_from_nodename(node_name: str, logger) -> Optional[int]:
    now = time.time()
    cached = _DEVICE_ID_CACHE.get(node_name)
    if cached and (now - cached[1] < _DEVICE_ID_CACHE_TTL_SEC):
        logger.debug(f"{node_name}: using cached NetBox device_id={cached[0]}")
        return cached[0]

    base = _netbox_object_lookup_url()
    if not base:
        _throttled_info(
            logger,
            node_name,
            "nb_object_type_unsupported",
            f"{node_name}: NB_OBJECT_TYPE={NB_OBJECT_TYPE} unsupported; skipping NetBox journaling.",
        )
        _DEVICE_ID_CACHE[node_name] = (None, now)
        NETBOX_LOOKUPS.labels(result="unsupported_type").inc()
        return None

    resp = None
    try:
        resp = _NB.get(
            base,
            params={"name": node_name},
            timeout=NETBOX_TIMEOUT_SEC,
        )
        resp.raise_for_status()
        data = resp.json()

        count = data.get("count", 0)
        if count > 0:
            dev_id = data["results"][0]["id"]
            logger.info(f"{node_name}: resolved NetBox object id={dev_id}")
            _DEVICE_ID_CACHE[node_name] = (dev_id, now)
            NETBOX_LOOKUPS.labels(result="found").inc()
            return dev_id

        logger.warning(f"{node_name}: no NetBox object found with exact name={node_name}")
        NETBOX_LOOKUPS.labels(result="not_found").inc()

    except Exception as e:
        logger.warning(f"{node_name}: NetBox lookup failed: {e}; response={_resp_text(resp)}")
        NETBOX_LOOKUPS.labels(result="error").inc()

    _DEVICE_ID_CACHE[node_name] = (None, now)
    return None

def _post_netbox_journal(device_id: int, message: str, logger=None) -> bool:
    payload_new = {
        "assigned_object_type": _assigned_object_type(),
        "assigned_object_id": device_id,
        "kind": "info",
        "comments": message,
    }

    resp = None
    try:
        resp = _NB.post(
            f"{NB_URL}/api/extras/journal-entries/",
            json=payload_new,
            timeout=NETBOX_TIMEOUT_SEC,
        )

        if resp.status_code == 404 and NB_OBJECT_TYPE == "dcim.device":
            payload_old = {"kind": "info", "comments": message}
            resp = _NB.post(
                f"{NB_URL}/api/dcim/devices/{device_id}/journal/",
                json=payload_old,
                timeout=NETBOX_TIMEOUT_SEC,
            )

        resp.raise_for_status()
        NETBOX_JOURNAL_POSTS.labels(result="success").inc()
        if logger:
            logger.info(f"NetBox journal post succeeded for device_id={device_id}")
        return True

    except Exception as e:
        NETBOX_JOURNAL_POSTS.labels(result="error").inc()
        if logger:
            logger.warning(
                f"NetBox journal post failed for device_id={device_id}: {e}; response={_resp_text(resp)}"
            )
        return False

def _netbox_get_journal(
    device_id: int,
    lookback_hours: Optional[int] = None,
    logger=None,
) -> list:
    since = None
    if lookback_hours is not None:
        since = _utcnow() - timedelta(hours=lookback_hours)

    out = []

    resp = None
    try:
        resp = _NB.get(
            f"{NB_URL}/api/extras/journal-entries/",
            params={
                "assigned_object_type": _assigned_object_type(),
                "assigned_object_id": device_id,
                "limit": 200,
                "ordering": "-created",
            },
            timeout=NETBOX_TIMEOUT_SEC,
        )
        if resp.status_code == 200:
            res = resp.json()
            for row in res.get("results", []):
                created = row.get("created")
                cdt = _parse_rfc3339(created) if created else None
                if since and cdt and cdt < since:
                    continue
                out.append({
                    "id": row.get("id"),
                    "created": created,
                    "comments": row.get("comments", ""),
                })
            return out
    except Exception as e:
        if logger:
            logger.warning(
                f"NetBox extras journal fetch failed for device_id={device_id}: {e}; response={_resp_text(resp)}"
            )

    if NB_OBJECT_TYPE != "dcim.device":
        return out

    resp = None
    try:
        resp = _NB.get(
            f"{NB_URL}/api/dcim/devices/{device_id}/journal/",
            params={"limit": 200, "ordering": "-created"},
            timeout=NETBOX_TIMEOUT_SEC,
        )
        resp.raise_for_status()
        res = resp.json()
        for row in res.get("results", []):
            created = row.get("created")
            cdt = _parse_rfc3339(created) if created else None
            if since and cdt and cdt < since:
                continue
            out.append({
                "id": row.get("id"),
                "created": created,
                "comments": row.get("comments", ""),
            })
        return out
    except Exception as e:
        if logger:
            logger.warning(
                f"NetBox legacy journal fetch failed for device_id={device_id}: {e}; response={_resp_text(resp)}"
            )
        return out

def _netbox_get_recent_journal(device_id: int, lookback_hours: int, logger=None) -> list:
    return _netbox_get_journal(device_id, lookback_hours=lookback_hours, logger=logger)

def _delete_netbox_journal_entry(entry_id: int, logger=None) -> bool:
    resp = None
    try:
        resp = _NB.delete(
            f"{NB_URL}/api/extras/journal-entries/{entry_id}/",
            timeout=NETBOX_TIMEOUT_SEC,
        )
        if resp.status_code in (204, 200, 202):
            NETBOX_JOURNAL_DELETES.labels(result="success").inc()
            return True

        resp.raise_for_status()
        NETBOX_JOURNAL_DELETES.labels(result="success").inc()
        return True
    except Exception as e:
        code = getattr(resp, "status_code", None)
        if code in (403, 405):
            NETBOX_JOURNAL_DELETES.labels(result="not_allowed").inc()
            if logger:
                logger.warning(
                    f"NetBox journal delete not allowed for entry_id={entry_id}: status={code}; response={_resp_text(resp)}"
                )
            return False

        NETBOX_JOURNAL_DELETES.labels(result="error").inc()
        if logger:
            logger.warning(
                f"NetBox journal delete failed for entry_id={entry_id}: {e}; response={_resp_text(resp)}"
            )
        return False

def _maybe_cleanup_old_operator_journal_entries(device_id: int, logger=None) -> None:
    if not device_id:
        return

    now = time.time()
    last = _NETBOX_CLEANUP_LAST.get(device_id, 0.0)
    if now - last < NETBOX_CLEANUP_EVERY_SEC:
        return
    _NETBOX_CLEANUP_LAST[device_id] = now

    cutoff = _utcnow() - timedelta(days=NETBOX_RETENTION_DAYS)

    try:
        entries = _netbox_get_journal(device_id, lookback_hours=None, logger=logger)
        if not entries:
            NETBOX_CLEANUPS.labels(result="noop").inc()
            return

        delete_candidates = []
        for e in entries:
            entry_id = e.get("id")
            comments = e.get("comments", "") or ""
            created_dt = _parse_rfc3339(e.get("created", ""))

            if not entry_id or not created_dt:
                continue
            if created_dt >= cutoff:
                continue
            if not _is_operator_comment(comments):
                continue

            delete_candidates.append(entry_id)

        if not delete_candidates:
            NETBOX_CLEANUPS.labels(result="noop").inc()
            return

        deleted = 0
        for entry_id in delete_candidates:
            if _delete_netbox_journal_entry(entry_id, logger=logger):
                deleted += 1

        if deleted > 0:
            NETBOX_CLEANUPS.labels(result="success").inc()
            if logger:
                logger.info(
                    f"NetBox cleanup removed {deleted} old operator journal entr{'y' if deleted == 1 else 'ies'} for device_id={device_id}"
                )
        else:
            NETBOX_CLEANUPS.labels(result="noop").inc()

    except Exception as e:
        NETBOX_CLEANUPS.labels(result="error").inc()
        if logger:
            logger.warning(f"NetBox cleanup failed for device_id={device_id}: {e}")

def _fingerprint_exists(device_id: int, fingerprint: str, lookback_hours: int, logger=None) -> bool:
    needle = f"fingerprint={fingerprint}".lower()
    entries = _netbox_get_recent_journal(device_id, lookback_hours, logger=logger)
    for e in entries:
        c = (e.get("comments", "") or "").lower()
        if needle in c:
            if logger:
                logger.debug(f"Found existing NetBox journal fingerprint={fingerprint} for device_id={device_id}")
            return True
    return False

def _journal_once(device_id: int, message: str, fingerprint: str, lookback_hours: int, logger=None) -> bool:
    if not device_id or not fingerprint:
        if logger:
            logger.warning(
                f"Skipping journal_once due to missing device_id or fingerprint: device_id={device_id}, fingerprint={fingerprint}"
            )
        return False

    if not _reserve_local_fingerprint(fingerprint):
        if logger:
            logger.debug(f"Skipping local duplicate journal fingerprint={fingerprint}")
        return False

    try:
        if _fingerprint_exists(device_id, fingerprint, lookback_hours, logger=logger):
            if logger:
                logger.debug(f"Skipping duplicate journal entry fingerprint={fingerprint}")
            return False

        if "fingerprint=" not in message:
            message = f"{message} fingerprint={fingerprint}"

        ok = _post_netbox_journal(device_id, message, logger=logger)
        if ok:
            _maybe_cleanup_old_operator_journal_entries(device_id, logger=logger)
            return True

        _release_local_fingerprint(fingerprint)
        return False
    except Exception:
        _release_local_fingerprint(fingerprint)
        raise

def _bootid_seen_recently(device_id: int, boot_id: str, lookback_hours: int, logger=None) -> bool:
    needle = f"bootid={boot_id}".lower()
    entries = _netbox_get_recent_journal(device_id, lookback_hours, logger=logger)
    for e in entries:
        c = (e.get("comments", "") or "").lower()
        if needle in c:
            if logger:
                logger.debug(f"Found existing recent bootid={boot_id} in NetBox journal for device_id={device_id}")
            return True
    return False

def _parse_journal_created(entry: Dict[str, Any]) -> Optional[datetime]:
    created = entry.get("created")
    if not created:
        return None
    return _parse_rfc3339(created)

def _journal_has_tag(comment: str, tag: str) -> bool:
    if not comment:
        return False
    return tag.lower() in comment.lower()

def _count_stuck_deletes_since_last_reboot(device_id: int, lookback_hours: int, logger=None) -> int:
    entries = _netbox_get_recent_journal(device_id, lookback_hours, logger=logger)
    if not entries:
        return 0

    parsed = []
    for e in entries:
        created_dt = _parse_journal_created(e)
        parsed.append({
            "created_dt": created_dt,
            "comments": e.get("comments", "") or "",
        })

    parsed.sort(key=lambda x: x["created_dt"] or datetime.min.replace(tzinfo=timezone.utc))

    last_reboot_dt = None
    for e in parsed:
        if _journal_has_tag(e["comments"], TAG_REBOOT_CONFIRMED):
            last_reboot_dt = e["created_dt"]

    stuck_count = 0
    for e in parsed:
        if not _journal_has_tag(e["comments"], TAG_STUCK_DELETED):
            continue
        if last_reboot_dt is None or (e["created_dt"] and e["created_dt"] > last_reboot_dt):
            stuck_count += 1

    if logger:
        logger.debug(
            f"device_id={device_id}: stuck_delete_count_since_last_reboot={stuck_count}, "
            f"last_reboot_dt={last_reboot_dt.isoformat() if last_reboot_dt else 'none'}"
        )

    return stuck_count

# -------------------- K8s CR helpers --------------------
def _delete_snr_cr(name: str, namespace: str, logger) -> bool:
    crd = k8s.CustomObjectsApi()
    try:
        crd.delete_namespaced_custom_object(
            group="self-node-remediation.medik8s.io",
            version="v1alpha1",
            namespace=namespace,
            plural="selfnoderemediations",
            name=name,
        )
        logger.warning(f"{name}: successfully deleted SelfNodeRemediation CR.")
        return True
    except Exception as e:
        logger.warning(f"{name}: failed to delete SNR CR: {e}")
        return False

def _list_snr_objects(logger=None) -> List[Dict[str, Any]]:
    crd = k8s.CustomObjectsApi()
    try:
        res = crd.list_namespaced_custom_object(
            group="self-node-remediation.medik8s.io",
            version="v1alpha1",
            namespace=SNR_NAMESPACE,
            plural="selfnoderemediations",
        )
        return res.get("items", []) or []
    except Exception as e:
        if logger:
            logger.warning(f"Failed to list SelfNodeRemediation objects in namespace={SNR_NAMESPACE}: {e}")
        return []

# -------------------- Skip-log throttling --------------------
def _throttled_log(logger, node_name: str, key: str, msg: str, every_sec: int) -> None:
    now = time.time()
    k = f"{node_name}|{key}"
    last = _LOG_LAST.get(k, 0.0)
    if now - last >= every_sec:
        _LOG_LAST[k] = now
        logger.info(msg)

def _throttled_info(logger, node_name: str, key: str, msg: str) -> None:
    _throttled_log(logger, node_name, key, msg, SKIP_LOG_EVERY_SEC)

def _throttled_blocked(logger, node_name: str, key: str, msg: str) -> None:
    _throttled_log(logger, node_name, key, msg, BLOCKED_LOG_EVERY_SEC)

# -------------------- Journal message formatters --------------------
def _format_gpufailed_incident(
    node_name: str,
    cond: Dict[str, Any],
    pci: Optional[str],
    xid: Optional[str],
    fp: str,
) -> str:
    reason = _squash_ws(cond.get("reason", "")) or "unknown"
    transition = _fmt_ts(cond.get("lastTransitionTime", ""))
    human = _extract_human_msg(cond.get("message", ""))
    msg_part = f' msg="{human}"' if human else ""
    pci_part = pci or "unknown"
    xid_part = xid or "unknown"
    return (
        f"{TAG_GPUFAILED_INCIDENT} "
        f"node={node_name} "
        f"reason={reason} "
        f"pci={pci_part} "
        f"xid={xid_part} "
        f"transition={transition}"
        f"{msg_part} "
        f"fingerprint={fp}"
    )

def _format_reboot_confirmed(node_name: str, boot_id: str, incident_fp: str, cr_name: str, fp: str) -> str:
    return (
        f"{TAG_REBOOT_CONFIRMED} "
        f"node={node_name} "
        f"bootid={boot_id} "
        f"incident_fp={incident_fp} "
        f"cr={cr_name} "
        f"fingerprint={fp}"
    )

def _format_auto_delete_blocked(node_name: str, stuck_count: int, cr_name: str, fp: str) -> str:
    return (
        f"{TAG_AUTO_DELETE_BLOCKED} "
        f"node={node_name} "
        f"stuck_delete_count={stuck_count} "
        f"cr={cr_name} "
        f"reason=three_failed_unsticks_no_reboot "
        f"fingerprint={fp}"
    )

# -------------------- GPU Power Management --------------------
def _netbox_get_gpu_inventory(device_id: int, logger=None) -> Dict[str, Any]:
    """Query NetBox inventory items for a device and return GPU count + model.
    Filters by NVIDIA manufacturer or common GPU name keywords."""
    resp = None
    try:
        resp = _NB.get(
            f"{NB_URL}/api/dcim/inventory-items/",
            params={"device_id": device_id, "limit": 200},
            timeout=NETBOX_TIMEOUT_SEC,
        )
        resp.raise_for_status()
        items = resp.json().get("results", [])

        gpu_names = []
        for item in items:
            name = (item.get("name") or "").lower()
            mfr  = ""
            if item.get("manufacturer"):
                m = item["manufacturer"]
                mfr = (m.get("name") or m.get("display") or "").lower()

            is_gpu = "nvidia" in mfr or any(kw in name for kw in [
                "geforce", "rtx", "gtx", "quadro", "tesla",
                "a100", "h100", "ga10", "ad10", "tu10", "gp10",
            ])
            if is_gpu:
                gpu_names.append(item.get("name") or "")

        model = ""
        if gpu_names:
            from collections import Counter
            model = Counter(gpu_names).most_common(1)[0][0]

        return {"count": len(gpu_names), "model": model}

    except Exception as e:
        if logger:
            logger.warning(f"NetBox GPU inventory fetch failed for device_id={device_id}: {e}; response={_resp_text(resp)}")
        return {}


def _count_reboots_24h_netbox(device_id: int, logger=None) -> int:
    """Count TAG_REBOOT_CONFIRMED journal entries in the last 24 h for this device."""
    entries = _netbox_get_recent_journal(device_id, lookback_hours=24, logger=logger)
    return sum(1 for e in entries if _journal_has_tag(e.get("comments", ""), TAG_REBOOT_CONFIRMED))


def _get_gpu_model_from_node(node_obj: k8s.V1Node) -> str:
    if not node_obj or not node_obj.metadata:
        return ""
    labels = node_obj.metadata.labels or {}
    return labels.get("nvidia.com/gpu.product", "")


def _node_has_gpus(node_obj: k8s.V1Node) -> bool:
    try:
        cap = node_obj.status.capacity or {}
        return int(cap.get("nvidia.com/gpu", "0") or "0") > 0
    except Exception:
        return False


def _annotate_node_power_policy(node_name: str, pct: int, logger) -> bool:
    core = k8s.CoreV1Api()
    try:
        body = {
            "metadata": {
                "annotations": {
                    "gpu-power-mgmt/target-limit-pct": str(pct),
                    "gpu-power-mgmt/policy-set-at": _fmt_ts(_utcnow()),
                }
            }
        }
        core.patch_node(node_name, body)
        logger.info(f"{node_name}: annotated gpu-power-mgmt/target-limit-pct={pct}")
        return True
    except Exception as e:
        logger.warning(f"{node_name}: failed to patch node power annotation: {e}")
        return False


def _post_to_webui(url: str, payload: dict, retries: int = 2) -> bool:
    """POST to the web UI with simple retry. Returns True if successful."""
    for attempt in range(retries):
        try:
            r = requests.post(url, json=payload, timeout=5)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        if attempt < retries - 1:
            time.sleep(2)
    return False


def _log_operator_event(
    node_name: str,
    event_type: str,
    severity: str,
    message: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Post a filtered, high-signal operator event to the web UI for display in the dashboard."""
    if not WEB_UI_URL:
        return
    _post_to_webui(
        f"{WEB_UI_URL}/api/events/operator-log",
        {
            "node_name": node_name,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "metadata": metadata or {},
        },
    )


def _log_reboot_to_webui(
    node_name: str,
    boot_id: str,
    reboot_count: int,
    gpu_model: str,
    power_pct_applied: Optional[int],
) -> bool:
    if not WEB_UI_URL:
        return False
    return _post_to_webui(
        f"{WEB_UI_URL}/api/events/reboot",
        {
            "node_name": node_name,
            "boot_id": boot_id,
            "reboot_count_24h": reboot_count,
            "gpu_model": gpu_model,
            "power_pct_applied": power_pct_applied,
        },
    )


def _handle_gpu_power_on_reboot(
    node_name: str,
    node_obj: k8s.V1Node,
    device_id: Optional[int],
    boot_id: str,
    logger,
) -> None:
    """After a confirmed reboot: detect storm, annotate node with target power pct, log to web UI."""
    if not _node_has_gpus(node_obj):
        return

    gpu_model = _get_gpu_model_from_node(node_obj)

    reboot_count = 0
    if device_id:
        reboot_count = _count_reboots_24h_netbox(device_id, logger=logger)

    pct = GPU_POWER_LIMIT_PCT_STORM if reboot_count >= GPU_STORM_THRESHOLD else GPU_POWER_LIMIT_PCT_NORMAL

    annotated = _annotate_node_power_policy(node_name, pct, logger)
    if annotated:
        GPU_POWER_ANNOTATIONS.labels(node=node_name, pct=str(pct)).inc()
        if reboot_count >= GPU_STORM_THRESHOLD:
            logger.warning(
                f"{node_name}: GPU reboot storm ({reboot_count} reboots in 24h); "
                f"power limit set to {pct}% gpu_model={gpu_model or 'unknown'}"
            )
            _log_operator_event(
                node_name, "reboot_storm", "critical",
                f"Reboot storm: {reboot_count} reboots in 24h — power throttled to {pct}%",
                {"reboot_count": reboot_count, "power_pct": pct, "gpu_model": gpu_model},
            )

    _log_reboot_to_webui(node_name, boot_id, reboot_count, gpu_model, pct if annotated else None)


# -------------------- Core logic --------------------
def _handle_one_snr(body: Dict[str, Any], name: str, namespace: str, logger) -> None:
    if namespace != SNR_NAMESPACE:
        logger.debug(f"{name}: namespace={namespace} does not match SNR_NAMESPACE={SNR_NAMESPACE}; skipping.")
        return

    deletion_ts = body.get("metadata", {}).get("deletionTimestamp")
    if deletion_ts:
        logger.debug(f"{name}: CR is already being deleted; skipping processing.")
        return

    node_name = _resolve_node_name_from_cr(name, body, logger=logger)
    if not node_name:
        logger.warning(f"{name}: cannot resolve backing Node; skipping.")
        SNR_EVENTS.labels(node=name, action="resolve_failed").inc()
        return

    core = k8s.CoreV1Api()
    try:
        node_obj = core.read_node(node_name)
    except Exception as e:
        logger.warning(f"{node_name}: cannot read node; skipping. {e}")
        SNR_EVENTS.labels(node=node_name, action="node_read_failed").inc()
        return

    matching_skip_taints = _matching_skip_taints(node_obj)
    if matching_skip_taints:
        _throttled_info(
            logger,
            node_name,
            "skip_taint",
            f"{node_name}: skipped due to taint(s) {matching_skip_taints}.",
        )
        SNR_EVENTS.labels(node=node_name, action="skipped_taint").inc()
        return

    creation_ts = body.get("metadata", {}).get("creationTimestamp", "")
    cr_dt = _parse_rfc3339(creation_ts)
    cr_uid = body.get("metadata", {}).get("uid", "")
    cr_age_min = int((_utcnow() - cr_dt).total_seconds() / 60) if cr_dt else None

    device_id = _device_id_from_nodename(node_name, logger)
    if not device_id:
        logger.warning(f"{node_name}: no NetBox object id resolved; journaling will be skipped for this pass.")

    # A) GPUFailed incident (deduped)
    cond = _get_gpufailed_condition(node_obj)
    gpufailed_now = cond is not None
    incident_fp = None

    if gpufailed_now:
        incident_fp = _incident_fingerprint(node_name, cond)
        pci_id, xid = _extract_gpu_ids_from_message(cond.get("message", "") or "")

        if device_id:
            msg = _format_gpufailed_incident(node_name, cond, pci_id, xid, incident_fp)
            if _journal_once(device_id, msg, incident_fp, LOOKBACK_HOURS, logger=logger):
                logger.info(f"{node_name}: journaled GPUFailed incident fp={incident_fp}")
                SNR_EVENTS.labels(node=node_name, action="gpufailed_incident_logged").inc()
                _log_operator_event(
                    node_name, "gpufailed", "warning",
                    f"GPU failure detected — xid={xid or 'unknown'} pci={pci_id or 'unknown'}",
                    {"xid": xid, "pci": pci_id, "reason": cond.get("reason", "")},
                )
        else:
            logger.warning(f"{node_name}: cannot journal GPUFailed incident because device_id is missing.")

    # B) Reboot confirmed via bootID (only when GPUFailed now or recently)
    gpufailed_recent = gpufailed_now or _gpufailed_true_recently(node_name, logger=logger)
    boot_id = _get_node_boot_id(node_obj)

    if device_id and boot_id and gpufailed_recent:
        if not _bootid_seen_recently(device_id, boot_id, LOOKBACK_HOURS, logger=logger):
            assoc_fp = incident_fp or "none"
            reboot_fp = _sha1(f"reboot_confirmed|{node_name}|{assoc_fp}|{boot_id}")
            msg = _format_reboot_confirmed(node_name, boot_id, assoc_fp, name, reboot_fp)
            if _journal_once(device_id, msg, reboot_fp, LOOKBACK_HOURS, logger=logger):
                logger.info(f"{node_name}: journaled reboot-confirmed bootid={boot_id}")
                SNR_EVENTS.labels(node=node_name, action="reboot_confirmed").inc()
                # D) GPU power management: annotate node with target power limit + log reboot to web UI
                _handle_gpu_power_on_reboot(node_name, node_obj, device_id, boot_id, logger)
    elif device_id and boot_id and boot_id not in _webui_reboot_boot_ids_sent:
        # Reboot detected but gpufailed not recent — still log to web UI for visibility,
        # but skip power annotation (no GPU fault associated with this reboot).
        if not _bootid_seen_recently(device_id, boot_id, LOOKBACK_HOURS, logger=logger):
            gpu_model = _get_gpu_model_from_node(node_obj)
            if _log_reboot_to_webui(node_name, boot_id, 0, gpu_model, None):
                _webui_reboot_boot_ids_sent.add(boot_id)

    # C) Optional remediation: delete stuck SNR CRs
    if ENABLE_ACTIVE_REMEDIATION and cr_age_min is not None and gpufailed_recent:
        node_bad_state = _node_unreachable_or_notready(node_obj)

        if cr_age_min >= STUCK_GRACE_MIN and node_bad_state:
            _throttled_blocked(
                logger,
                node_name,
                "stuck_suppressed_unreachable",
                f"{node_name}: stuck candidate suppressed (node unreachable/not-ready). CR age={cr_age_min}m.",
            )
            SNR_EVENTS.labels(node=node_name, action="stuck_suppressed_unreachable").inc()

        if cr_age_min >= STUCK_DELETE_AFTER_MIN:
            node_unsched = _node_unschedulable(node_obj)

            if node_bad_state:
                _throttled_blocked(
                    logger,
                    node_name,
                    "stuck_delete_blocked_unreachable",
                    f"{node_name}: NOT deleting stuck SNR CR (node unreachable/not-ready). CR age={cr_age_min}m.",
                )
                SNR_EVENTS.labels(node=node_name, action="stuck_delete_blocked_unreachable").inc()

            elif node_unsched:
                _throttled_blocked(
                    logger,
                    node_name,
                    "stuck_delete_blocked_unschedulable",
                    f"{node_name}: NOT deleting stuck SNR CR (node unschedulable). CR age={cr_age_min}m.",
                )
                SNR_EVENTS.labels(node=node_name, action="stuck_delete_blocked_unschedulable").inc()

            else:
                stuck_delete_count = 0
                if device_id:
                    stuck_delete_count = _count_stuck_deletes_since_last_reboot(
                        device_id,
                        LOOKBACK_HOURS,
                        logger=logger,
                    )

                if stuck_delete_count >= 3:
                    _throttled_blocked(
                        logger,
                        node_name,
                        "stuck_delete_blocked_repeated_failures",
                        f"{node_name}: NOT deleting stuck SNR CR; found {stuck_delete_count} prior "
                        f"{TAG_STUCK_DELETED} journal entries since last {TAG_REBOOT_CONFIRMED}. "
                        f"Manual admin review required.",
                    )
                    SNR_AUTO_DELETE_BLOCKS.labels(node=node_name).inc()
                    SNR_EVENTS.labels(node=node_name, action="stuck_delete_blocked_repeated_failures").inc()
                    _log_operator_event(
                        node_name, "manual_review_required", "critical",
                        f"Manual review required: {stuck_delete_count} stuck SNR deletions with no successful reboot",
                        {"stuck_count": stuck_delete_count, "cr": name, "cr_age_min": cr_age_min},
                    )

                    if device_id:
                        fp = _sha1(f"snr_auto_delete_blocked|{node_name}|{name}|{cr_uid}|{stuck_delete_count}")
                        msg = _format_auto_delete_blocked(node_name, stuck_delete_count, name, fp)
                        _journal_once(device_id, msg, fp, LOOKBACK_HOURS, logger=logger)

                else:
                    ok = _delete_snr_cr(name, namespace, logger)
                    if ok:
                        SNR_STUCK_DELETES.labels(node=node_name).inc()
                        SNR_EVENTS.labels(node=node_name, action="stuck_deleted").inc()
                        logger.warning(f"{node_name}: deleted stuck SNR CR {name} age={cr_age_min}m")
                        _log_operator_event(
                            node_name, "stuck_snr_deleted", "warning",
                            f"Stuck SNR CR deleted after {cr_age_min}m — node failed to reboot cleanly",
                            {"cr": name, "cr_age_min": cr_age_min},
                        )

                        if device_id and cr_uid:
                            fp = _sha1(f"snr_stuck_deleted|{node_name}|{cr_uid}|{name}")
                            msg = (
                                f"{TAG_STUCK_DELETED} "
                                f"node={node_name} age_min={cr_age_min} cr={name} uid={cr_uid} fingerprint={fp}"
                            )
                            _journal_once(device_id, msg, fp, LOOKBACK_HOURS, logger=logger)
                    else:
                        SNR_EVENTS.labels(node=node_name, action="stuck_delete_failed").inc()

# -------------------- Stateless event + sweep model --------------------
def _run_periodic_sweep(logger) -> None:
    while True:
        try:
            items = _list_snr_objects(logger=logger)
            for body in items:
                meta = body.get("metadata", {}) or {}
                name = meta.get("name")
                namespace = meta.get("namespace", SNR_NAMESPACE)
                if not name:
                    continue
                try:
                    _handle_one_snr(body, name, namespace, logger)
                except Exception as e:
                    logger.warning(f"{name}: periodic sweep processing failed: {e}")
        except Exception as e:
            logger.warning(f"Periodic SNR sweep failed: {e}")

        time.sleep(SNR_SWEEP_PERIOD_SEC)

@kopf.on.event("self-node-remediation.medik8s.io", "v1alpha1", "selfnoderemediations")
def on_snr_event(event, body, name, namespace, logger, **_):
    event_type = (event or {}).get("type")
    if event_type == "DELETED":
        return
    _handle_one_snr(body, name, namespace, logger)

# -------------------- NetBox inventory sync --------------------
def _sync_netbox_inventory_to_webui(logger) -> None:
    """One-time startup task: for every GPU node in the cluster, query NetBox
    inventory to get expected GPU count and POST it to the web UI for display."""
    try:
        v1 = k8s.CoreV1Api()
        nodes = v1.list_node(label_selector="nvidia.com/gpu.present=true").items
        logger.info(f"NetBox inventory sync: {len(nodes)} GPU nodes found")
    except Exception as e:
        logger.warning(f"NetBox inventory sync: failed to list nodes: {e}")
        return

    synced = 0
    for node in nodes:
        node_name = node.metadata.name
        try:
            device_id = _device_id_from_nodename(node_name, logger)
            if not device_id:
                continue
            inv = _netbox_get_gpu_inventory(device_id, logger)
            if not inv or not inv.get("count"):
                continue
            _post_to_webui(
                f"{WEB_UI_URL}/api/nodes/sync-netbox",
                {
                    "node_name":           node_name,
                    "netbox_device_id":    device_id,
                    "expected_gpu_count":  inv["count"],
                    "expected_gpu_model":  inv["model"],
                },
            )
            synced += 1
        except Exception as e:
            logger.warning(f"NetBox inventory sync: failed for {node_name}: {e}")

    logger.info(f"NetBox inventory sync complete: {synced}/{len(nodes)} nodes synced to web UI")


# -------------------- Kopf handlers --------------------
@kopf.on.startup()
def _startup(settings: kopf.OperatorSettings, logger, **_):
    global _SWEEP_THREAD_STARTED

    settings.posting.enabled = False

    try:
        logging.getLogger("kopf.objects").setLevel(
            getattr(logging, KOPF_OBJECTS_LOG_LEVEL, logging.WARNING)
        )
    except Exception:
        pass

    logger.info("snr-netbox-watcher started")
    kubernetes.config.load_incluster_config()
    start_http_server(METRICS_PORT)

    with _SWEEP_THREAD_LOCK:
        if not _SWEEP_THREAD_STARTED:
            t = threading.Thread(
                target=_run_periodic_sweep,
                args=(logger,),
                name="snr-periodic-sweep",
                daemon=True,
            )
            t.start()
            _SWEEP_THREAD_STARTED = True

    if WEB_UI_URL:
        threading.Thread(
            target=_sync_netbox_inventory_to_webui,
            args=(logger,),
            name="netbox-inventory-sync",
            daemon=True,
        ).start()

    logger.info(
        f"Configuration: SNR_NAMESPACE={SNR_NAMESPACE}, NB_OBJECT_TYPE={NB_OBJECT_TYPE}, "
        f"PROM_URL={'set' if PROM_URL else 'unset'}, ENABLE_ACTIVE_REMEDIATION={ENABLE_ACTIVE_REMEDIATION}, "
        f"SNR_SWEEP_PERIOD_SEC={SNR_SWEEP_PERIOD_SEC}, LOOKBACK_HOURS={LOOKBACK_HOURS}, "
        f"TAINT_SKIP_KEYS={sorted(TAINT_SKIP_KEYS)}, BLOCKED_LOG_EVERY_SEC={BLOCKED_LOG_EVERY_SEC}, "
        f"LOCAL_FP_TTL_SEC={LOCAL_FP_TTL_SEC}, NETBOX_RETENTION_DAYS={NETBOX_RETENTION_DAYS}, "
        f"NETBOX_CLEANUP_EVERY_SEC={NETBOX_CLEANUP_EVERY_SEC}, KOPF_OBJECTS_LOG_LEVEL={KOPF_OBJECTS_LOG_LEVEL}"
    )