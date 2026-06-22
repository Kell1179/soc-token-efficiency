"""
compressor.py — Strategi compression log sebelum masuk LLM.

Strategy 1: baseline          — tidak ada compression
Strategy 2: dedup             — exact deduplication (eventId + userId)
Strategy 3: severity_filter   — hanya sus == 1
Strategy 4: near_dedup        — grouping berdasarkan (eventId, returnValue bucket)
Strategy 5: trend_detection   — burst events diganti summary count
Strategy 6: incident_cluster  — grouping per processId, filter PID anomalous
Strategy 7: whitelist_suppress — buang eventId known-benign di BETH
"""

from collections import defaultdict
from rich.console import Console

console = Console()

# ---------------------------------------------------------------------------
# BETH known-benign eventIds (syscall yang rutin dan tidak berbahaya)
# Referensi: BETH dataset paper + Linux syscall table
# ---------------------------------------------------------------------------
BENIGN_EVENT_IDS = {
    0,    # read
    1,    # write
    3,    # close
    5,    # fstat
    9,    # mmap
    10,   # mprotect
    11,   # munmap
    12,   # brk
    21,   # access
    39,   # getpid
    72,   # fcntl (sebagian besar benign)
    89,   # readdir
    96,   # gettimeofday
    97,   # getrlimit
    102,  # getuid
    104,  # getgid
    107,  # geteuid
    108,  # getegid
    158,  # arch_prctl
    231,  # exit_group
    257,  # openat (log-heavy tapi sering benign)
}

# Threshold burst: kalau eventId yang sama muncul lebih dari ini dalam batch,
# anggap sebagai "trend" dan ringkas jadi satu baris summary
BURST_THRESHOLD = 10


# ---------------------------------------------------------------------------
# Strategy 1: Baseline
# ---------------------------------------------------------------------------

def compress_baseline(logs: list[dict]) -> list[dict]:
    """Tidak ada filtering. Semua log diteruskan apa adanya."""
    return logs


# ---------------------------------------------------------------------------
# Strategy 2: Exact deduplication
# ---------------------------------------------------------------------------

def compress_dedup(logs: list[dict]) -> list[dict]:
    """
    Hapus duplikat berdasarkan (eventId, userId).
    Prioritaskan representatif yang evil=1 jika ada.
    """
    seen: dict[tuple, dict] = {}
    for log in logs:
        key = (log["eventId"], log["userId"])
        if key not in seen:
            seen[key] = log
        elif log["evil"] == 1 and seen[key]["evil"] == 0:
            seen[key] = log
    return list(seen.values())


# ---------------------------------------------------------------------------
# Strategy 3: Severity filter
# ---------------------------------------------------------------------------

def compress_severity_filter(logs: list[dict]) -> list[dict]:
    """Hanya teruskan log yang sus == 1."""
    return [log for log in logs if log["sus"] == 1]


# ---------------------------------------------------------------------------
# Strategy 4: Near-duplicate grouping
# ---------------------------------------------------------------------------

def compress_near_dedup(logs: list[dict]) -> list[dict]:
    """
    Grouping berdasarkan (eventId, userId, returnValue bucket).
    returnValue di-bucket: success (>=0) vs error (<0).
    Lebih halus dari exact dedup — masih pisahkan success vs error call.
    Prioritaskan representatif evil=1 jika ada dalam group.
    """
    seen: dict[tuple, dict] = {}
    for log in logs:
        ret_bucket = "ok" if log["returnValue"] >= 0 else "err"
        key = (log["eventId"], log["userId"], ret_bucket)
        if key not in seen:
            seen[key] = log
        elif log["evil"] == 1 and seen[key]["evil"] == 0:
            seen[key] = log
    return list(seen.values())


# ---------------------------------------------------------------------------
# Strategy 5: Trend detection
# ---------------------------------------------------------------------------

def compress_trend_detection(logs: list[dict]) -> list[dict]:
    """
    Deteksi burst: eventId yang muncul > BURST_THRESHOLD kali
    diganti dengan satu log synthetic berisi count summary.
    Event di bawah threshold tetap dikirim apa adanya.
    """
    event_counts: dict[int, list[dict]] = defaultdict(list)
    for log in logs:
        event_counts[log["eventId"]].append(log)

    result = []
    for evt_id, evt_logs in event_counts.items():
        if len(evt_logs) <= BURST_THRESHOLD:
            result.extend(evt_logs)
        else:
            # Cek apakah ada evil=1 dalam burst ini
            has_evil = any(l["evil"] == 1 for l in evt_logs)
            max_sus  = max(l["sus"] for l in evt_logs)
            # Buat satu log synthetic sebagai summary
            summary_log = evt_logs[0].copy()
            summary_log["_summary"]    = True
            summary_log["_count"]      = len(evt_logs)
            summary_log["evil"]        = 1 if has_evil else 0
            summary_log["sus"]         = max_sus
            result.append(summary_log)

    return result


# ---------------------------------------------------------------------------
# Strategy 6: Incident clustering
# ---------------------------------------------------------------------------

def compress_incident_cluster(logs: list[dict]) -> list[dict]:
    """
    Grouping log per processId.
    Hanya kirim PID yang dianggap anomalous:
    - punya minimal 1 log sus=1, ATAU
    - jumlah unique eventId > threshold (aktivitas beragam = suspicious)
    PID yang purely benign dibuang.
    """
    pid_groups: dict[int, list[dict]] = defaultdict(list)
    for log in logs:
        pid_groups[log["processId"]].append(log)

    result = []
    for pid, pid_logs in pid_groups.items():
        has_sus        = any(l["sus"] == 1 for l in pid_logs)
        unique_events  = len(set(l["eventId"] for l in pid_logs))
        is_anomalous   = has_sus or unique_events > 5

        if is_anomalous:
            # Dari PID ini, ambil hanya log yang paling representatif
            # (sus=1 duluan, lalu sisanya sampai max 5 per PID)
            sus_logs    = [l for l in pid_logs if l["sus"] == 1]
            other_logs  = [l for l in pid_logs if l["sus"] == 0]
            chosen      = (sus_logs + other_logs)[:5]
            result.extend(chosen)

    return result


# ---------------------------------------------------------------------------
# Strategy 7: Whitelist suppression
# ---------------------------------------------------------------------------

def compress_whitelist(logs: list[dict]) -> list[dict]:
    """
    Buang log dengan eventId yang known-benign (BENIGN_EVENT_IDS).
    Pengecualian: tetap simpan jika sus=1 atau evil=1,
    karena bahkan syscall benign bisa jadi anomalous dalam konteks tertentu.
    """
    result = []
    for log in logs:
        is_benign_event = log["eventId"] in BENIGN_EVENT_IDS
        is_flagged      = log["sus"] == 1 or log["evil"] == 1
        if not is_benign_event or is_flagged:
            result.append(log)
    return result


# ---------------------------------------------------------------------------
# Helper: format log ke string untuk prompt
# ---------------------------------------------------------------------------

def log_to_line(log: dict) -> str:
    """Konversi satu log dict ke satu baris teks ringkas."""
    if log.get("_summary"):
        return (
            f"[SUMMARY] evt={log['eventId']} "
            f"count={log['_count']} "
            f"sus={log['sus']} "
            f"pid={log['processId']}"
        )
    return (
        f"t={log['timestamp']} "
        f"pid={log['processId']} "
        f"uid={log['userId']} "
        f"evt={log['eventId']} "
        f"ret={log['returnValue']} "
        f"sus={log['sus']}"
    )


def logs_to_prompt_text(logs: list[dict]) -> str:
    return "\n".join(log_to_line(l) for l in logs)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

STRATEGIES = {
    "baseline"         : compress_baseline,
    "dedup"            : compress_dedup,
    "severity_filter"  : compress_severity_filter,
    "near_dedup"       : compress_near_dedup,
    "trend_detection"  : compress_trend_detection,
    "incident_cluster" : compress_incident_cluster,
    "whitelist"        : compress_whitelist,
}


def run_all_strategies(logs: list[dict]) -> dict[str, dict]:
    """
    Jalankan semua strategi, kembalikan hasilnya.
    Return: { strategy_name: { "logs": [...], "count": int, "text": str } }
    """
    results = {}
    for name, fn in STRATEGIES.items():
        compressed = fn(logs)
        text = logs_to_prompt_text(compressed)
        results[name] = {
            "logs" : compressed,
            "count": len(compressed),
            "text" : text,
        }
        console.print(
            f"[cyan]{name:<20}[/cyan] "
            f"{len(compressed):>5} logs  "
            f"({len(text):>8} chars)"
        )
    return results


# ---------------------------------------------------------------------------
# Quick test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from src.loader import load_beth, to_log_dicts

    df   = load_beth("data/raw/labelled_testing_data.csv", max_rows=1000)
    logs = to_log_dicts(df)

    console.print("\n[yellow]Hasil compression (dari 1000 logs):[/yellow]")
    run_all_strategies(logs)