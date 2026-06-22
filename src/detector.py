"""
detector.py — Baseline detector tanpa LLM.

Dua pendekatan:
1. Heuristic rules  — flag PID berdasarkan kondisi sederhana
2. Isolation Forest — ML-based anomaly detection (Highnam et al. 2021)

Referensi:
  Highnam et al. (2021) BETH Dataset: Real Cybersecurity Data for
  Unsupervised Anomaly Detection Research. CEUR-WS Vol-3095.

  Eremin (2025) Unsupervised Anomaly Detection on Cybersecurity Data
  Streams: A Case with BETH Dataset. IJOIT vol.13 no.6.
"""

from collections import defaultdict
from rich.console import Console

console = Console()

BURST_THRESHOLD = 20


# ---------------------------------------------------------------------------
# Helper: build PID profile
# ---------------------------------------------------------------------------

def build_pid_profiles(logs: list[dict]) -> dict[int, dict]:
    profiles = defaultdict(lambda: {
        "total": 0, "sus": 0, "evil": 0,
        "events": set(), "has_high_risk": False
    })
    for log in logs:
        p = log["processId"]
        profiles[p]["total"] += 1
        profiles[p]["sus"]   += log["sus"]
        profiles[p]["evil"]  += log["evil"]
        profiles[p]["events"].add(log["eventId"])
    return dict(profiles)


# ---------------------------------------------------------------------------
# Heuristic rules
# ---------------------------------------------------------------------------

def detect_rule_sus(profiles: dict) -> set[int]:
    """Flag PID yang punya minimal 1 log sus=1."""
    return {pid for pid, p in profiles.items() if p["sus"] > 0}


def detect_rule_eventid(profiles: dict) -> set[int]:
    """
    Flag PID yang pernah eksekusi eventId high-risk.
    Catatan: rule ini TIDAK divalidasi literatur untuk BETH —
    tidak ada paper yang pakai pendekatan ini. Disertakan untuk
    perbandingan saja.
    """
    HIGH_RISK = {59, 56, 322, 319, 263, 105, 106, 161, 281}
    return {pid for pid, p in profiles.items()
            if p["events"] & HIGH_RISK}


def detect_rule_combined(profiles: dict) -> set[int]:
    """Flag PID yang punya sus=1 DAN high-risk event."""
    HIGH_RISK = {59, 56, 322, 319, 263, 105, 106, 161, 281}
    return {pid for pid, p in profiles.items()
            if p["sus"] > 0 and (p["events"] & HIGH_RISK)}


def detect_rule_burst(profiles: dict) -> set[int]:
    """Flag PID yang jumlah log-nya melebihi BURST_THRESHOLD."""
    return {pid for pid, p in profiles.items()
            if p["total"] > BURST_THRESHOLD}


def detect_rule_all(profiles: dict) -> set[int]:
    """Union semua rule."""
    return (detect_rule_sus(profiles) |
            detect_rule_eventid(profiles) |
            detect_rule_burst(profiles))


RULES = {
    "rule_sus"      : detect_rule_sus,
    "rule_eventid"  : detect_rule_eventid,
    "rule_combined" : detect_rule_combined,
    "rule_burst"    : detect_rule_burst,
    "rule_all"      : detect_rule_all,
}


# ---------------------------------------------------------------------------
# Evaluasi heuristic rule
# ---------------------------------------------------------------------------

def evaluate_rule(predicted_pids: set[int], true_evil_pids: set[int],
                  rule_name: str, all_pids: set[int]) -> dict:
    tp = len(predicted_pids & true_evil_pids)
    fp = len(predicted_pids - true_evil_pids)
    fn = len(true_evil_pids - predicted_pids)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    return {
        "rule"           : rule_name,
        "predicted_pids" : sorted(predicted_pids),
        "true_evil_pids" : sorted(true_evil_pids),
        "tp": tp, "fp": fp, "fn": fn,
        "precision"      : round(precision, 3),
        "recall"         : round(recall, 3),
        "f1"             : round(f1, 3),
        "roc_auc"        : None,
        "input_tokens"   : 0,
        "total_tokens"   : 0,
        "token_savings"  : 100.0,
    }


# ---------------------------------------------------------------------------
# Isolation Forest (Highnam et al. 2021)
# ---------------------------------------------------------------------------

def build_feature_matrix(logs: list[dict]):
    """
    4 binary features dari paper asli BETH + eventId raw:
      processId_nonOS      : PID > 1000
      parentProcessId_nonOS: parent PID > 1000
      userId_nonOS         : userId >= 1000
      returnValue_error    : returnValue < 0
      eventId              : raw integer (tambahan kita)
    """
    import numpy as np

    rows, y, pids = [], [], []
    for log in logs:
        pid  = log["processId"]
        ppid = log.get("parentProcessId", 0) or 0
        uid  = log["userId"]
        ret  = log["returnValue"]
        evt  = log["eventId"]

        rows.append([
            int(pid  > 1000),
            int(ppid > 1000),
            int(uid  >= 1000),
            int(ret  < 0),
            evt,
        ])
        y.append(log["evil"])
        pids.append(pid)

    return np.array(rows, dtype=float), np.array(y), pids


def run_isolation_forest(logs: list[dict]) -> dict:
    """
    Isolation Forest per-event, agregasi ke level PID.
    ROC-AUC dihitung di level event (konsisten dengan literatur BETH).
    Precision/Recall/F1 dihitung di level PID.
    """
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics  import roc_auc_score

    X, y_true, pids = build_feature_matrix(logs)

    if len(set(y_true)) < 2:
        console.print("  [yellow]⚠ isolation_forest: tidak ada variasi label evil.[/yellow]")
        return {
            "rule": "isolation_forest", "tp": 0, "fp": 0, "fn": 0,
            "precision": 0.0, "recall": 0.0, "f1": 0.0, "roc_auc": 0.0,
            "input_tokens": 0, "total_tokens": 0, "token_savings": 100.0,
            "predicted_pids": [], "true_evil_pids": [],
        }

    clf = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    clf.fit(X)

    scores    = clf.score_samples(X)
    y_pred_01 = (clf.predict(X) == -1).astype(int)
    roc       = roc_auc_score(y_true, -scores)

    # Agregasi ke PID level
    pid_pred: dict[int, int] = {}
    pid_true: dict[int, int] = {}
    for i, pid in enumerate(pids):
        pid_pred[pid] = max(pid_pred.get(pid, 0), int(y_pred_01[i]))
        pid_true[pid] = max(pid_true.get(pid, 0), int(y_true[i]))

    all_pids_sorted     = sorted(pid_pred.keys())
    predicted_evil_pids = {p for p in all_pids_sorted if pid_pred[p] == 1}
    true_evil_pids      = {p for p in all_pids_sorted if pid_true[p] == 1}

    tp = len(predicted_evil_pids & true_evil_pids)
    fp = len(predicted_evil_pids - true_evil_pids)
    fn = len(true_evil_pids - predicted_evil_pids)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    console.print(
        f"  [cyan]{'isolation_forest':<20}[/cyan] "
        f"ROC-AUC={roc:.3f}  "
        f"P={precision:.3f}  R={recall:.3f}  F1={f1:.3f}  tokens=0"
    )

    return {
        "rule"           : "isolation_forest",
        "tp": tp, "fp": fp, "fn": fn,
        "precision"      : round(precision, 3),
        "recall"         : round(recall, 3),
        "f1"             : round(f1, 3),
        "roc_auc"        : round(roc, 3),
        "input_tokens"   : 0,
        "total_tokens"   : 0,
        "token_savings"  : 100.0,
        "predicted_pids" : sorted(predicted_evil_pids),
        "true_evil_pids" : sorted(true_evil_pids),
    }


# ---------------------------------------------------------------------------
# Run semua detector sekaligus
# ---------------------------------------------------------------------------

def run_all_rules(logs: list[dict]) -> list[dict]:
    profiles       = build_pid_profiles(logs)
    true_evil_pids = {pid for pid, p in profiles.items() if p["evil"] > 0}
    all_pids       = set(profiles.keys())

    console.print(f"\n  Ground truth evil PIDs: {sorted(true_evil_pids)}")
    console.print(f"  Total unique PIDs      : {len(all_pids)}\n")

    results = []

    # Heuristic rules
    for name, fn in RULES.items():
        predicted = fn(profiles)
        result    = evaluate_rule(predicted, true_evil_pids, name, all_pids)
        results.append(result)
        console.print(
            f"  [cyan]{name:<20}[/cyan] "
            f"predicted={len(predicted):>3} PIDs  "
            f"P={result['precision']:.3f}  "
            f"R={result['recall']:.3f}  "
            f"F1={result['f1']:.3f}  "
            f"tokens=0"
        )

    # Isolation Forest
    console.print()
    results.append(run_isolation_forest(logs))

    return results


# ---------------------------------------------------------------------------
# Quick test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from src.loader import load_beth, to_log_dicts
    from rich.table import Table

    df   = load_beth("data/raw/labelled_testing_data.csv", max_rows=1000)
    logs = to_log_dicts(df)

    console.rule("[bold cyan]Baseline Detector (Rule-based + Isolation Forest)[/bold cyan]")
    results = run_all_rules(logs)

    table = Table(title="Baseline Results", show_lines=True)
    table.add_column("Detector",  style="cyan")
    table.add_column("TP",        justify="right")
    table.add_column("FP",        justify="right")
    table.add_column("FN",        justify="right")
    table.add_column("Precision", justify="right")
    table.add_column("Recall",    justify="right")
    table.add_column("F1",        justify="right", style="yellow")
    table.add_column("ROC-AUC",   justify="right", style="cyan")
    table.add_column("Tokens",    justify="right", style="green")

    for r in results:
        table.add_row(
            r["rule"],
            str(r["tp"]), str(r["fp"]), str(r["fn"]),
            str(r["precision"]), str(r["recall"]), str(r["f1"]),
            str(r["roc_auc"]) if r["roc_auc"] is not None else "—",
            "0 (no LLM)",
        )

    console.print(table)