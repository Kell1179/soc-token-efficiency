"""
evaluator.py — Ukur token efficiency dan kualitas deteksi per strategi.

Metrik yang diukur:
- Token savings vs baseline (%)
- Precision, Recall, F1 terhadap ground truth evil=1
- Threat level yang dihasilkan LLM
"""

from rich.console import Console
from rich.table import Table

console = Console()


def evaluate(
    llm_results: list[dict],
    compressed_data: dict[str, dict],
    original_logs: list[dict],
) -> list[dict]:
    """
    Hitung metrik per strategi.

    Args:
        llm_results     : output dari call_llm() per strategi
        compressed_data : output dari run_all_strategies()
        original_logs   : logs asli sebelum compression (untuk ground truth)

    Returns:
        list of dict, satu entry per strategi
    """
    # Ground truth: PID yang benar-benar malicious (evil=1)
    true_evil_pids = set(
        log["processId"] for log in original_logs if log["evil"] == 1
    )

    baseline_tokens = None
    metrics = []

    for result in llm_results:
        strategy = result["strategy"]

        # Skip kalau ada error
        if result["error"]:
            metrics.append({
                "strategy"      : strategy,
                "error"         : result["error"],
                "input_tokens"  : 0,
                "output_tokens" : 0,
                "total_tokens"  : 0,
                "token_savings" : 0.0,
                "precision"     : 0.0,
                "recall"        : 0.0,
                "f1"            : 0.0,
                "threat_level"  : "N/A",
                "log_count"     : 0,
            })
            continue

        input_tokens  = result["input_tokens"]
        output_tokens = result["output_tokens"]
        total_tokens  = result["total_tokens"]

        if strategy == "baseline":
            baseline_tokens = total_tokens

        # Token savings relatif ke baseline
        if baseline_tokens and baseline_tokens > 0:
            savings = (1 - total_tokens / baseline_tokens) * 100
        else:
            savings = 0.0

        # Precision & Recall dari malicious_pids yang diprediksi LLM
        response      = result["response"] or {}
        predicted_raw = response.get("malicious_pids", [])

        # Pastikan tipe data konsisten (int)
        predicted_pids = set()
        for p in predicted_raw:
            try:
                predicted_pids.add(int(p))
            except (ValueError, TypeError):
                pass

        if predicted_pids:
            tp = len(predicted_pids & true_evil_pids)
            fp = len(predicted_pids - true_evil_pids)
            fn = len(true_evil_pids - predicted_pids)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1        = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0 else 0.0
            )
        else:
            precision = recall = f1 = 0.0

        log_count = compressed_data.get(strategy, {}).get("count", 0)

        metrics.append({
            "strategy"      : strategy,
            "error"         : None,
            "input_tokens"  : input_tokens,
            "output_tokens" : output_tokens,
            "total_tokens"  : total_tokens,
            "token_savings" : round(savings, 1),
            "precision"     : round(precision, 3),
            "recall"        : round(recall, 3),
            "f1"            : round(f1, 3),
            "threat_level"  : response.get("threat_level", "N/A"),
            "log_count"     : log_count,
        })

    return metrics


def print_report(metrics: list[dict]) -> None:
    """Tampilkan tabel hasil evaluasi di terminal."""

    table = Table(title="SOC Token Efficiency — Hasil Eksperimen", show_lines=True)

    table.add_column("Strategy",       style="cyan",   no_wrap=True)
    table.add_column("Logs sent",      justify="right")
    table.add_column("Input tkn",      justify="right")
    table.add_column("Total tkn",      justify="right")
    table.add_column("Savings",        justify="right", style="green")
    table.add_column("Precision",      justify="right")
    table.add_column("Recall",         justify="right")
    table.add_column("F1",             justify="right", style="yellow")
    table.add_column("Threat level",   justify="center")

    for m in metrics:
        if m["error"]:
            table.add_row(
                m["strategy"], "—", "—", "—", "—", "—", "—", "—",
                f"[red]ERROR[/red]"
            )
            continue

        table.add_row(
            m["strategy"],
            str(m["log_count"]),
            str(m["input_tokens"]),
            str(m["total_tokens"]),
            f"{m['token_savings']}%",
            str(m["precision"]),
            str(m["recall"]),
            str(m["f1"]),
            m["threat_level"],
        )

    console.print(table)


def save_metrics(metrics: list[dict], filepath: str) -> None:
    """Simpan metrics ke JSON untuk keperluan analisis lebih lanjut."""
    import json
    import os

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(metrics, f, indent=2)

    console.print(f"[dim]Metrics saved → {filepath}[/dim]")