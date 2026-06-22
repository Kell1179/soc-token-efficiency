"""
analyze_recall.py — Investigasi kenapa incident_cluster bisa recall 1.0
Jalankan: python analyze_recall.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from collections import defaultdict
from rich.console import Console
from rich.table   import Table
from src.loader     import load_beth, to_log_dicts
from src.compressor import compress_incident_cluster, compress_dedup

console = Console()

df   = load_beth("data/raw/labelled_testing_data.csv", max_rows=1000)
logs = to_log_dicts(df)

evil_logs = [l for l in logs if l["evil"] == 1]
evil_pids  = set(l["processId"] for l in evil_logs)

console.print(f"\n[yellow]Ground truth:[/yellow]")
console.print(f"  Total evil=1 logs : {len(evil_logs)}")
console.print(f"  Unique evil PIDs  : {sorted(evil_pids)}")

# --- Profil semua PID ---
console.rule("Analisis 1 — Profil PID")
pid_stats = defaultdict(lambda: {"total": 0, "sus": 0, "evil": 0, "events": set()})
for log in logs:
    p = log["processId"]
    pid_stats[p]["total"] += 1
    pid_stats[p]["sus"]   += log["sus"]
    pid_stats[p]["evil"]  += log["evil"]
    pid_stats[p]["events"].add(log["eventId"])

table = Table(show_lines=True)
table.add_column("PID",           style="cyan")
table.add_column("Total logs",    justify="right")
table.add_column("sus=1 count",   justify="right")
table.add_column("evil=1 count",  justify="right")
table.add_column("Unique events", justify="right")
table.add_column("Evil PID?",     justify="center")
for pid in sorted(pid_stats):
    s = pid_stats[pid]
    table.add_row(str(pid), str(s["total"]), str(s["sus"]), str(s["evil"]),
                  str(len(s["events"])), "[red]YES[/red]" if pid in evil_pids else "no")
console.print(table)

# --- Kenapa evil PID lolos ---
console.rule("Analisis 2 — Kenapa evil PID lolos incident_cluster?")
for pid in sorted(evil_pids):
    s = pid_stats[pid]
    reasons = []
    if s["sus"] > 0:       reasons.append(f"punya sus=1 ({s['sus']} log)")
    if len(s["events"]) > 5: reasons.append(f"unique_events={len(s['events'])} > 5")
    console.print(f"  PID [cyan]{pid}[/cyan]: {', '.join(reasons) if reasons else 'TIDAK lolos!'}")

# --- False positive PIDs ---
console.rule("Analisis 3 — False positive PIDs")
clustered      = compress_incident_cluster(logs)
clustered_pids = set(l["processId"] for l in clustered)
fp_pids        = clustered_pids - evil_pids
console.print(f"  Total PID lolos cluster  : {len(clustered_pids)}")
console.print(f"  Evil PID (true positive) : {len(evil_pids & clustered_pids)}")
console.print(f"  Benign PID ikut lolos    : {len(fp_pids)}")
for pid in sorted(fp_pids):
    s = pid_stats[pid]
    console.print(f"    PID {pid}: sus={s['sus']} unique_events={len(s['events'])} total={s['total']}")

# --- Coverage per strategi ---
console.rule("Analisis 4 — Coverage evil PID per strategi")
deduped    = compress_dedup(logs)
dedup_pids = set(l["processId"] for l in deduped)
console.print(f"  Evil PIDs               : {sorted(evil_pids)}")
console.print(f"  Ada di dedup            : {sorted(evil_pids & dedup_pids)} ({len(evil_pids & dedup_pids)}/{len(evil_pids)})")
console.print(f"  Ada di cluster          : {sorted(evil_pids & clustered_pids)} ({len(evil_pids & clustered_pids)}/{len(evil_pids)})")
