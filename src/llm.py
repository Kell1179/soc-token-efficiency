"""
llm.py — Wrapper untuk Groq API.
"""

import json
import time
import os
from dotenv import load_dotenv
from groq import Groq
from rich.console import Console

load_dotenv()
console = Console()

MODEL = "llama-3.3-70b-versatile"
RATE_LIMIT_DELAY = 3


def get_client() -> Groq:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise EnvironmentError("GROQ_API_KEY tidak ditemukan di .env")
    return Groq(api_key=api_key)


def empty_result(strategy_name: str, reason: str) -> dict:
    """Return result tanpa API call — untuk kasus log kosong."""
    console.print(f"  [yellow]⚠ {strategy_name}: skip ({reason})[/yellow]")
    return {
        "strategy"     : strategy_name,
        "response"     : {"threat_level": "N/A", "malicious_pids": [], "summary": reason, "confidence": 0.0},
        "input_tokens" : 0,
        "output_tokens": 0,
        "total_tokens" : 0,
        "raw"          : "",
        "error"        : reason,
    }


def call_llm(messages: list[dict], strategy_name: str, log_count: int = -1) -> dict:
    """
    Kirim messages ke Groq dan kembalikan hasil beserta metadata token.

    Args:
        messages      : output dari build_prompt()
        strategy_name : nama strategi
        log_count     : jumlah log yang dikirim (untuk deteksi empty)
    """
    # Guard: jangan kirim ke LLM kalau log kosong
    if log_count == 0:
        return empty_result(strategy_name, "No logs after compression")

    client = get_client()
    result = {
        "strategy"     : strategy_name,
        "response"     : None,
        "input_tokens" : 0,
        "output_tokens": 0,
        "total_tokens" : 0,
        "raw"          : "",
        "error"        : None,
    }

    raw = ""
    try:
        console.print(f"  [dim]→ Calling LLM ({strategy_name})...[/dim]")

        completion = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            temperature=0.1,
            max_tokens=512,
        )

        raw = completion.choices[0].message.content.strip()
        result["raw"] = raw

        usage = completion.usage
        result["input_tokens"]  = usage.prompt_tokens
        result["output_tokens"] = usage.completion_tokens
        result["total_tokens"]  = usage.total_tokens

        # Bersihkan markdown code fence kalau ada
        clean = raw.strip("`").strip()
        if clean.startswith("json"):
            clean = clean[4:].strip()

        result["response"] = json.loads(clean)
        console.print(f"  [green]✓ {strategy_name}: {result['total_tokens']} tokens[/green]")

    except json.JSONDecodeError as e:
        result["error"] = f"JSON parse error: {e} | raw: {raw[:200]}"
        console.print(f"  [red]✗ JSON error ({strategy_name}): {e}[/red]")

    except Exception as e:
        result["error"] = str(e)
        console.print(f"  [red]✗ Error ({strategy_name}): {e}[/red]")

    finally:
        time.sleep(RATE_LIMIT_DELAY)

    return result


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from src.prompt import build_prompt

    sample_text = (
        "t=1000 pid=101 uid=0 evt=59 ret=0 sus=1\n"
        "t=1001 pid=102 uid=1000 evt=2 ret=0 sus=0\n"
        "t=1002 pid=103 uid=0 evt=59 ret=-1 sus=1"
    )

    messages = build_prompt(sample_text, "test")
    result   = call_llm(messages, "test", log_count=3)

    console.print("\n[yellow]Token usage:[/yellow]")
    console.print(f"  Input  : {result['input_tokens']}")
    console.print(f"  Output : {result['output_tokens']}")
    console.print(f"  Total  : {result['total_tokens']}")
    console.print("\n[yellow]LLM Response:[/yellow]")
    console.print(result["response"])