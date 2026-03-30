"""
gpu-power-agent: DaemonSet agent that runs on every GPU node.

Reads the node annotation `gpu-power-mgmt/target-limit-pct` set by the
snr-netbox-watcher operator and applies the corresponding power limit to
all NVIDIA GPUs via nvidia-smi.  After applying, it writes back
`gpu-power-mgmt/applied-limit-watts` and `gpu-power-mgmt/applied-at`
annotations and logs the event to the web-ui API.
"""
import os
import sys
import time
import logging
import subprocess
from datetime import datetime, timezone
from typing import Optional

import requests
from kubernetes import client, config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("gpu-power-agent")

NODE_NAME: str = os.environ.get("NODE_NAME", "")
POLL_INTERVAL_SEC: int = int(os.environ.get("POLL_INTERVAL_SEC", "60"))
WEB_UI_URL: str = os.environ.get("WEB_UI_URL", "").rstrip("/")
DEFAULT_POWER_LIMIT_PCT: int = int(os.environ.get("DEFAULT_POWER_LIMIT_PCT", "100"))

if not NODE_NAME:
    log.error("NODE_NAME env var is required (set via Downward API fieldRef spec.nodeName)")
    sys.exit(1)


# ---------- nvidia-smi helpers ----------

def _run_smi(*args: str, timeout: int = 15) -> Optional[str]:
    try:
        r = subprocess.run(
            ["nvidia-smi", *args],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode != 0:
            log.warning(f"nvidia-smi {' '.join(args)} failed: {r.stderr.strip()}")
            return None
        return r.stdout.strip()
    except FileNotFoundError:
        log.error("nvidia-smi not found – is this a GPU node?")
        return None
    except Exception as e:
        log.warning(f"nvidia-smi error: {e}")
        return None


def get_gpu_count() -> int:
    out = _run_smi("--query-gpu=index", "--format=csv,noheader")
    if not out:
        return 0
    return len([l for l in out.splitlines() if l.strip()])


def get_gpu_info() -> list[dict]:
    """Returns list of {index, name, max_power_w, current_power_limit_w}."""
    out = _run_smi(
        "--query-gpu=index,name,power.max_limit,power.limit",
        "--format=csv,noheader,nounits",
    )
    if not out:
        return []
    gpus = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4:
            continue
        try:
            gpus.append({
                "index": int(parts[0]),
                "name": parts[1],
                "max_power_w": int(float(parts[2])),
                "current_limit_w": int(float(parts[3])),
            })
        except (ValueError, IndexError):
            pass
    return gpus


def apply_power_limit(gpu_index: int, watts: int) -> bool:
    out = _run_smi("-i", str(gpu_index), "-pl", str(watts), timeout=30)
    if out is not None:
        log.info(f"GPU {gpu_index}: set power limit to {watts}W")
        return True
    return False


# ---------- Kubernetes helpers ----------

def read_node_annotations() -> dict:
    v1 = client.CoreV1Api()
    node = v1.read_node(NODE_NAME)
    return node.metadata.annotations or {}


def patch_node_annotations(patches: dict) -> None:
    v1 = client.CoreV1Api()
    v1.patch_node(NODE_NAME, {"metadata": {"annotations": patches}})


# ---------- Web UI logging ----------

def _log_power_event_to_webui(
    gpu_index: int,
    gpu_name: str,
    old_limit_w: int,
    new_limit_w: int,
    target_pct: int,
    status: str,
) -> None:
    if not WEB_UI_URL:
        return
    try:
        requests.post(
            f"{WEB_UI_URL}/api/events/power-limit",
            json={
                "node_name": NODE_NAME,
                "gpu_index": gpu_index,
                "gpu_model": gpu_name,
                "old_power_limit_watts": old_limit_w,
                "new_power_limit_watts": new_limit_w,
                "target_pct": target_pct,
                "status": status,
            },
            timeout=5,
        )
    except Exception:
        pass


# ---------- Main loop ----------

def _utcnow_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def apply_policy_if_needed(annotations: dict) -> None:
    raw_pct = annotations.get("gpu-power-mgmt/target-limit-pct", str(DEFAULT_POWER_LIMIT_PCT))
    try:
        target_pct = int(raw_pct)
    except ValueError:
        log.warning(f"Invalid gpu-power-mgmt/target-limit-pct value: {raw_pct!r}; using {DEFAULT_POWER_LIMIT_PCT}")
        target_pct = DEFAULT_POWER_LIMIT_PCT

    gpus = get_gpu_info()
    if not gpus:
        log.info("No GPUs detected on this node – nothing to do.")
        return

    applied_watts_list = []
    all_ok = True

    for gpu in gpus:
        max_w = gpu["max_power_w"]
        target_w = max(1, int(max_w * target_pct / 100))
        ok = apply_power_limit(gpu["index"], target_w)
        status = "applied" if ok else "failed"
        _log_power_event_to_webui(
            gpu_index=gpu["index"],
            gpu_name=gpu["name"],
            old_limit_w=gpu["current_limit_w"],
            new_limit_w=target_w,
            target_pct=target_pct,
            status=status,
        )
        if ok:
            applied_watts_list.append(str(target_w))
        else:
            all_ok = False

    annotation_patches = {
        "gpu-power-mgmt/applied-limit-watts": ",".join(applied_watts_list),
        "gpu-power-mgmt/applied-at": _utcnow_str(),
        "gpu-power-mgmt/applied-pct": str(target_pct),
        "gpu-power-mgmt/apply-status": "ok" if all_ok else "partial",
    }
    try:
        patch_node_annotations(annotation_patches)
    except Exception as e:
        log.warning(f"Failed to write applied annotations: {e}")


def run() -> None:
    log.info(f"gpu-power-agent starting on node={NODE_NAME} poll_interval={POLL_INTERVAL_SEC}s")
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()

    last_pct: Optional[str] = None

    while True:
        try:
            annotations = read_node_annotations()
            current_pct = annotations.get(
                "gpu-power-mgmt/target-limit-pct",
                str(DEFAULT_POWER_LIMIT_PCT),
            )
            # Apply on startup (last_pct is None) or whenever the annotation changes
            if current_pct != last_pct:
                log.info(f"Power policy changed: {last_pct!r} -> {current_pct!r}; applying...")
                apply_policy_if_needed(annotations)
                last_pct = current_pct
        except Exception as e:
            log.warning(f"Error in main loop: {e}")

        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    run()
