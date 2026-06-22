"""
main.py — Entry point. Jalankan full pipeline eksperimen.

Usage:
    python main.py
    python main.py --rows 2000 --skip 5000
    python main.py --rows 1000 --max-logs 150
"""

import argparse
import datetime
import sys
import os

from rich.console import Console
from rich.table   import Table

sys.path.insert(0, os.path.dirname(__file__))

from src.loader     import load_beth, to_log_dicts
from src.compressor import run_all_strategies
from src.prompt     import build_prompt
from src.llm        import call_llm
from src.evaluator  import evaluate, save_metrics
from src.detector   import run_all_rules

console = Console()


def parse_args():
    parser = argparse.ArgumentParser(description="SOC Token Efficiency Experiment")
    parser.add_argument("--rows",     type=int, default=1000)
    parser.add_argument("--skip",     type=int, default=0)
    parser.add_argument("--max-logs", type=int, default=200)
    parser.add_argument("--data",     type=str,
                        default="data/raw/labelled_testing_data.csv")
    return parser.parse_args()


def print_full_report(llm_metrics: list[dict], rule_metrics: list[dict],
                      baseline_tokens: int) -> None:
    """Tabel gabungan: rule-based + LLM strategies."""

    table = Table(
        title="SOC Detection — Rule-based vs LLM Strategies",
        show_lines=True
    )
    table.add_column("Strategy",     style="cyan", no_wrap=True)
    table.add_column("Type",         justify="center")
    table.add_column("Logs sent",    justify="right")
    table.add_column("Total tokens", justify="right")
    table.add_column("Savings",      justify="right", style="green")
    table.add_column("Precision",    justify="right")
    table.add_column("Recall",       justify="right")
    table.add_column("F1",           justify="right", style="yellow")
    table.add_column("ROC-AUC",      justify="right")

    # Rule-based rows (0 token, 100% savings)
    for r in rule_metrics:
        roc = f"{r['roc_auc']:.3f}" if r.get("roc_auc") else "—"
        table.add_row(
            r["rule"],
            "[dim]rule[/dim]",
            "—",
            "[green]0[/green]",
            "[green]100%[/green]",
            str(r["precision"]),
            str(r["recall"]),
            str(r["f1"]),
            roc,
        )

    # LLM strategy rows
    for m in llm_metrics:
        if m.get("error") and m["total_tokens"] == 0:
            table.add_row(
                m["strategy"], "[dim]LLM[/dim]",
                "—", "—", "—", "—", "—", "[red]ERROR[/red]", "—"
            )
            continue

        savings_str = f"{m['token_savings']}%"
        table.add_row(
            m["strategy"],
            "[dim]LLM[/dim]",
            str(m["log_count"]),
            str(m["total_tokens"]),
            savings_str,
            str(m["precision"]),
            str(m["recall"]),
            str(m["f1"]),
            "—",
        )

    console.print(table)


def main():
    args = parse_args()

    console.rule("[bold cyan]SOC Token Efficiency Experiment[/bold cyan]")
    console.print(f"Dataset  : {args.data}")
    console.print(f"Rows     : {args.rows} (skip={args.skip})")
    console.print(f"Max logs : {args.max_logs} per strategi")
    console.print()

    # ------------------------------------------------------------------ #
    # 1. Load dataset
    # ------------------------------------------------------------------ #
    console.rule("Step 1 — Load dataset")
    df   = load_beth(args.data, max_rows=args.rows, skip_rows=args.skip)
    logs = to_log_dicts(df)

    # ------------------------------------------------------------------ #
    # 2. Rule-based baseline (no LLM, no token cost)
    # ------------------------------------------------------------------ #
    console.rule("Step 2 — Rule-based baseline (0 tokens)")
    rule_metrics = run_all_rules(logs)

    # ------------------------------------------------------------------ #
    # 3. Compress dengan semua strategi
    # ------------------------------------------------------------------ #
    console.rule("Step 3 — Compression")
    compressed = run_all_strategies(logs)

    # ------------------------------------------------------------------ #
    # 4. Kirim ke LLM per strategi
    # ------------------------------------------------------------------ #
    console.rule("Step 4 — LLM calls")
    llm_results = []

    for strategy_name, data in compressed.items():
        logs_to_send = data["logs"][:args.max_logs]
        log_count    = len(logs_to_send)

        log_text = "\n".join([
            f"t={l['timestamp']} pid={l['processId']} uid={l['userId']} "
            f"evt={l['eventId']} ret={l['returnValue']} sus={l['sus']}"
            for l in logs_to_send
        ])

        messages = build_prompt(log_text, strategy_name)
        result   = call_llm(messages, strategy_name, log_count=log_count)
        llm_results.append(result)

    # ------------------------------------------------------------------ #
    # 5. Evaluasi LLM
    # ------------------------------------------------------------------ #
    console.rule("Step 5 — Evaluation")
    llm_metrics     = evaluate(llm_results, compressed, logs)
    baseline_tokens = next(
        (m["total_tokens"] for m in llm_metrics if m["strategy"] == "baseline"), 0
    )

    # ------------------------------------------------------------------ #
    # 6. Tampilkan laporan gabungan & simpan
    # ------------------------------------------------------------------ #
    console.rule("Step 6 — Results")
    print_full_report(llm_metrics, rule_metrics, baseline_tokens)

    timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"results/runs/run_{timestamp}.json"

    # Gabung rule + LLM metrics ke satu file
    combined = [
        {**r, "total_tokens": 0, "input_tokens": 0,
         "token_savings": 100.0, "log_count": 0,
         "strategy": r["rule"], "threat_level": "N/A", "error": None}
        for r in rule_metrics
    ] + llm_metrics

    save_metrics(combined, output_path)
    console.rule("[bold green]Done[/bold green]")


if __name__ == "__main__":
    main()