"""
run_pipeline.py — Jalankan hanya pipeline kombinasi + baseline sebagai pembanding.

Usage:
    python run_pipeline.py
    python run_pipeline.py --rows 1000 --max-logs 200
"""

import argparse
import datetime
import sys
import os

from rich.console import Console

sys.path.insert(0, os.path.dirname(__file__))

from src.loader     import load_beth, to_log_dicts
from src.compressor import (
    compress_baseline,
    compress_pipeline_a,
    compress_pipeline_b,
    compress_pipeline_c,
    logs_to_prompt_text,
)
from src.prompt     import build_prompt
from src.llm        import call_llm
from src.evaluator  import evaluate, print_report, save_metrics

console = Console()

TARGETS = {
    "baseline"                   : compress_baseline,
    "pipeline_a_wl+cluster"      : compress_pipeline_a,
    "pipeline_b_wl+cluster+dedup": compress_pipeline_b,
    "pipeline_c_wl+trend+cluster": compress_pipeline_c,
}


def parse_args():
    parser = argparse.ArgumentParser(description="Run pipeline combination strategies only")
    parser.add_argument("--rows",     type=int, default=1000)
    parser.add_argument("--max-logs", type=int, default=200)
    parser.add_argument("--data",     type=str,
                        default="data/raw/labelled_testing_data.csv")
    return parser.parse_args()


def main():
    args = parse_args()

    console.rule("[bold cyan]Pipeline Combination Experiment[/bold cyan]")
    console.print(f"Dataset  : {args.data}")
    console.print(f"Rows     : {args.rows}")
    console.print(f"Max logs : {args.max_logs} per strategi")
    console.print(f"Strategies: {list(TARGETS.keys())}")
    console.print()

    # Load
    console.rule("Step 1 — Load dataset")
    df   = load_beth(args.data, max_rows=args.rows)
    logs = to_log_dicts(df)

    # Compress
    console.rule("Step 2 — Compression")
    compressed = {}
    for name, fn in TARGETS.items():
        result = fn(logs)
        text   = logs_to_prompt_text(result)
        compressed[name] = {"logs": result, "count": len(result), "text": text}
        console.print(
            f"[cyan]{name:<30}[/cyan] "
            f"{len(result):>5} logs  "
            f"({len(text):>8} chars)"
        )

    # LLM calls
    console.rule("Step 3 — LLM calls")
    llm_results = []
    for name, data in compressed.items():
        logs_to_send = data["logs"][:args.max_logs]
        log_text = "\n".join([
            f"t={l['timestamp']} pid={l['processId']} uid={l['userId']} "
            f"evt={l['eventId']} ret={l['returnValue']} sus={l['sus']}"
            for l in logs_to_send
        ])
        messages = build_prompt(log_text, name)
        result   = call_llm(messages, name, log_count=len(logs_to_send))
        llm_results.append(result)

    # Evaluate
    console.rule("Step 4 — Results")
    metrics = evaluate(llm_results, compressed, logs)
    print_report(metrics)

    timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"results/runs/pipeline_{timestamp}.json"
    save_metrics(metrics, output_path)

    console.rule("[bold green]Done[/bold green]")


if __name__ == "__main__":
    main()