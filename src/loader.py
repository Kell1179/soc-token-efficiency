import pandas as pd
import os
from rich.console import Console

console = Console()

REQUIRED_COLS = [
    "timestamp", "processId", "threadId", "parentProcessId",
    "userId", "mountNamespace", "eventId", "argsNum",
    "returnValue", "sus", "evil"
]

def load_beth(filepath: str, max_rows: int = 5000, skip_rows: int = 0) -> pd.DataFrame:
    """
    Load BETH dataset dari CSV.

    Args:
        max_rows : jumlah baris yang diload
        skip_rows: skip N baris pertama (untuk cari bagian dataset yang ada evil=1)
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File tidak ditemukan: {filepath}")

    console.print(f"[cyan]Loading BETH dataset dari:[/cyan] {filepath}")

    if skip_rows > 0:
        # Baca header dulu, lalu skip
        df = pd.read_csv(filepath, skiprows=range(1, skip_rows + 1), nrows=max_rows)
    else:
        df = pd.read_csv(filepath, nrows=max_rows)

    # Validasi kolom
    missing = [c for c in REQUIRED_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Kolom tidak ditemukan di dataset: {missing}")

    console.print(f"[green]✓ Loaded {len(df)} rows (skip={skip_rows})[/green]")
    console.print(f"  Suspicious events : {df['sus'].sum()}")
    console.print(f"  Malicious events  : {df['evil'].sum()}")

    if df['evil'].sum() == 0:
        console.print(f"  [yellow]⚠ Tidak ada evil=1 di range ini. Coba --skip lebih besar.[/yellow]")

    return df


def to_log_dicts(df: pd.DataFrame) -> list[dict]:
    """
    Konversi DataFrame ke list of dict — format yang akan masuk ke compressor.
    Hanya ambil kolom yang relevan secara security.
    """
    cols = ["timestamp", "processId", "userId", "eventId",
            "returnValue", "sus", "evil"]
    return df[cols].to_dict(orient="records")


if __name__ == "__main__":
    # Quick test
    df = load_beth("data/raw/labelled_training_data.csv", max_rows=1000)
    logs = to_log_dicts(df)
    console.print(f"\n[yellow]Contoh log entry:[/yellow]")
    console.print(logs[0])