"""
prompt.py — Builder untuk prompt yang dikirim ke LLM.

Sistem prompt menginstruksikan LLM untuk bertindak sebagai SOC analyst
dan menganalisis log yang diberikan, lalu output dalam format JSON terstruktur.
"""

SYSTEM_PROMPT = """You are a Security Operations Center (SOC) analyst.
You will be given a list of system call logs from a Linux host.
Each log line contains: timestamp, process ID, user ID, event ID, return value, and suspicious flag.

Your job:
1. Identify which events look malicious or anomalous.
2. Assign an overall threat level: LOW, MEDIUM, or HIGH.
3. Return ONLY a valid JSON object — no explanation, no markdown, no extra text.

Output format:
{
  "threat_level": "LOW" | "MEDIUM" | "HIGH",
  "malicious_pids": [list of suspicious processIds as integers],
  "summary": "one sentence explanation",
  "confidence": 0.0 to 1.0
}"""


def build_prompt(log_text: str, strategy_name: str) -> list[dict]:
    """
    Bangun messages array untuk dikirim ke Groq API.

    Args:
        log_text     : output dari logs_to_prompt_text()
        strategy_name: nama strategi (untuk context, tidak masuk prompt)

    Returns:
        list of message dicts siap kirim ke client.chat.completions.create()
    """
    user_content = f"Analyze the following system call logs:\n\n{log_text}"

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": user_content},
    ]


def estimate_token_count(text: str) -> int:
    """
    Estimasi kasar jumlah token dari sebuah string.
    Aturan praktis: 1 token ≈ 4 karakter untuk bahasa Inggris / log ASCII.
    Ini bukan angka exact — hanya untuk perbandingan antar strategi.
    """
    return len(text) // 4


if __name__ == "__main__":
    # Quick test
    sample_text = (
        "t=1000 pid=101 uid=0 evt=59 ret=0 sus=1\n"
        "t=1001 pid=102 uid=1000 evt=2 ret=0 sus=0\n"
        "t=1002 pid=103 uid=0 evt=59 ret=-1 sus=1"
    )

    messages = build_prompt(sample_text, strategy_name="baseline")

    print("=== System prompt ===")
    print(messages[0]["content"])
    print("\n=== User message (preview) ===")
    print(messages[1]["content"][:200])
    print("\n=== Estimasi token ===")
    full_text = messages[0]["content"] + messages[1]["content"]
    print(f"{estimate_token_count(full_text)} tokens (estimasi)")