"""
core/baseline/engine.py

User & Host Behavioral Baseline Engine
Role: Compares current behavior against historical norms.
      Answers: "Is it unusual for jdoe to run PowerShell?"
      Answers: "Has WORKSTATION-01 ever connected to 185.220.101.45?"

In prototype: uses a static mock baseline dict.
In production: queries the baselines table in SQLite, updated by a background job
               that processes historical telemetry.

Output: BaselineResult — feeds into anomaly scoring.
"""
from models.schemas import BaselineResult, RuntimeContext
from utils.logger import get_logger

log = get_logger("baseline_engine")

# ── Mock baseline profiles ────────────────────────────────────────────────────
# In production these come from the DB, computed over 30-day rolling windows.
# Format: { "user@host": { feature: probability } }
MOCK_BASELINES: dict[str, dict[str, float]] = {
    "jdoe@WORKSTATION-01": {
        "runs_powershell": 0.02,        # 2% of sessions — very rare
        "runs_cmd": 0.05,
        "pdf_reader_spawns_script": 0.0,  # never observed
        "connects_to_external_ip": 0.10,
    },
    "admin@SERVER-01": {
        "runs_powershell": 0.80,
        "runs_cmd": 0.70,
        "pdf_reader_spawns_script": 0.0,
        "connects_to_external_ip": 0.30,
    },
}

DEFAULT_BASELINE = {
    "runs_powershell": 0.10,
    "runs_cmd": 0.15,
    "pdf_reader_spawns_script": 0.01,
    "connects_to_external_ip": 0.20,
}

# Threshold below which we consider behavior "unusual"
RARITY_THRESHOLD = 0.05


def _get_profile(user: str, host: str) -> dict[str, float]:
    key = f"{user}@{host}"
    return MOCK_BASELINES.get(key, DEFAULT_BASELINE)


def compute_baseline(user: str, host: str, runtime: RuntimeContext) -> BaselineResult:
    """
    Compare observed runtime behavior against the user+host baseline.

    Logic:
      1. Look up the baseline profile for user@host
      2. Check each observed behavior against its historical frequency
      3. Compute per-feature anomaly flags
      4. Compute aggregate anomaly scores
    """
    profile = _get_profile(user, host)

    # Did the user run PowerShell in this session?
    ran_powershell = any("powershell" in p.lower() for p in runtime.child_processes)
    ran_cmd = any("cmd" in p.lower() for p in runtime.child_processes)

    # Did the PDF reader spawn any script process?
    pdf_spawned_script = len(runtime.child_processes) > 0

    # Did the process connect to an external destination?
    has_external_connection = len(runtime.network_destinations) > 0

    # Rarity = 1 - frequency (how unusual is this behavior?)
    ps_rarity = 1.0 - profile.get("runs_powershell", 0.10)
    spawn_rarity = 1.0 - profile.get("pdf_reader_spawns_script", 0.01)

    # User anomaly score: weighted sum of unusual behaviors
    user_anomaly = 0.0
    if ran_powershell and profile.get("runs_powershell", 0.10) < RARITY_THRESHOLD:
        user_anomaly += 0.4
    if ran_cmd and profile.get("runs_cmd", 0.15) < RARITY_THRESHOLD:
        user_anomaly += 0.2
    if pdf_spawned_script and profile.get("pdf_reader_spawns_script", 0.01) < RARITY_THRESHOLD:
        user_anomaly += 0.4

    # Host anomaly: has this host connected to these destinations before?
    # In prototype: any external connection from a temp-path process is anomalous
    host_anomaly = 0.3 if has_external_connection else 0.0

    log.info(
        f"Baseline for {user}@{host}: ps_rarity={ps_rarity:.2f}, "
        f"user_anomaly={user_anomaly:.2f}, host_anomaly={host_anomaly:.2f}"
    )

    return BaselineResult(
        user_usually_runs_powershell=profile.get("runs_powershell", 0.10) > RARITY_THRESHOLD,
        user_usually_runs_cmd=profile.get("runs_cmd", 0.15) > RARITY_THRESHOLD,
        host_seen_destination_before=False,  # simplified; in prod: DB lookup
        pdf_reader_spawning_scripts_rarity=round(spawn_rarity, 2),
        user_anomaly_score=round(min(user_anomaly, 1.0), 2),
        host_anomaly_score=round(min(host_anomaly, 1.0), 2),
    )
