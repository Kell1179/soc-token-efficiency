# SOC Token Efficiency

Eksperimen untuk mengukur trade-off antara **token compression** dan **detection quality** pada pipeline AI-integrated Security Operations Center (SOC).

Pipeline ini mensimulasikan alur SOC alert: log dari dataset BETH (real Kubernetes honeypot) dikompresi dengan berbagai strategi sebelum dikirim ke LLM, lalu kualitas deteksinya diukur menggunakan precision, recall, dan F1.

---

## Latar Belakang

Salah satu barrier terbesar dalam SOC automation berbasis LLM adalah **volume log yang sangat besar**. Sebuah Kubernetes cluster produksi bisa menghasilkan ratusan ribu events per jam — mengirim semuanya ke LLM bukan hanya mahal, tapi seringkali melampaui context window model.

Project ini mengeksplorasi pertanyaan: **seberapa banyak log bisa dikompresi sebelum LLM kehilangan kemampuan mendeteksi ancaman?**

---

## Demo

```
baseline         1000 logs  →  4781 tokens  |  F1: 0.667  Recall: 1.0
dedup              48 logs  →  1373 tokens  |  F1: 0.364  Recall: 0.667   (-71.3% token)
near_dedup         53 logs  →  1484 tokens  |  F1: 0.364  Recall: 0.667   (-69.0% token)
incident_cluster   65 logs  →  1791 tokens  |  F1: 0.500  Recall: 1.0     (-62.5% token)
trend_detection    74 logs  →  1967 tokens  |  F1: 0.182  Recall: 0.333   (-58.8% token)
whitelist         695 logs  →  4839 tokens  |  F1: 0.667  Recall: 1.0     (-1.3%  token)
severity_filter   461 logs  →  4897 tokens  |  F1: 0.000  Recall: 0.0     (-2.4%  token)
```

---

## Struktur Project

```
soc-token-efficiency/
├── data/
│   └── raw/                      # Dataset BETH (tidak di-commit)
├── src/
│   ├── loader.py                 # Load & parse BETH dataset
│   ├── compressor.py             # 7 strategi compression + 3 pipeline kombinasi
│   ├── prompt.py                 # Prompt builder untuk LLM
│   ├── llm.py                    # Wrapper Groq API
│   └── evaluator.py              # Hitung token savings, precision, recall, F1
├── results/
│   └── runs/                     # Output JSON per eksperimen (auto-generated)
├── main.py                       # Entry point eksperimen
├── analyze_recall.py             # Deep-dive analisis per strategi
├── visualize_results.py          # Generate dashboard HTML dari hasil run
├── FINDINGS.md                   # Dokumentasi temuan eksperimen
├── requirements.txt
└── .env.example
```

---

## Strategi Compression

| Strategi | Cara kerja | Token savings |
|---|---|---|
| `baseline` | Semua log dikirim tanpa filter | 0% |
| `dedup` | Hapus duplikat berdasarkan `(eventId, userId)` | ~71% |
| `near_dedup` | Hapus duplikat berdasarkan `(eventId, userId, returnValue bucket)` | ~69% |
| `severity_filter` | Hanya kirim log dengan `sus=1` | ~0% (dataset-dependent) |
| `trend_detection` | Burst events (>10x) diganti satu baris summary count | ~59% |
| `incident_cluster` | Grouping per PID, hanya PID anomalous yang dikirim | ~63% |
| `whitelist` | Buang syscall known-benign kecuali yang flagged | ~0% (dataset-dependent) |
| `pipeline_a` | whitelist → incident_cluster | TBD |
| `pipeline_b` | whitelist → incident_cluster → dedup | TBD |
| `pipeline_c` | whitelist → trend_detection → incident_cluster | TBD |

---

## Quickstart

### 1. Clone & install

```bash
git clone https://github.com/username/soc-token-efficiency.git
cd soc-token-efficiency

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Setup API key

```bash
cp .env.example .env
# isi GROQ_API_KEY di file .env
```

Daftar gratis di [console.groq.com](https://console.groq.com) untuk mendapatkan API key.

### 3. Download dataset

Download **BETH dataset** dari [Kaggle](https://www.kaggle.com/datasets/katehighnam/beth-dataset), ambil file `labelled_testing_data.csv`, taruh di `data/raw/`.

> Dataset ini berisi real syscall logs dari Kubernetes honeypot environment dengan label `sus` (suspicious) dan `evil` (malicious ground truth).

### 4. Jalankan eksperimen

```bash
# Default: 1000 baris, max 200 log per strategi
python main.py --data data/raw/labelled_testing_data.csv

# Custom
python main.py --data data/raw/labelled_testing_data.csv --rows 2000 --max-logs 150

# Skip N baris pertama (untuk eksplor bagian dataset yang berbeda)
python main.py --data data/raw/labelled_testing_data.csv --skip 5000 --rows 1000
```

### 5. Visualisasi hasil

```bash
python visualize_results.py
# Buka results/summary.html di browser
```

### 6. Analisis mendalam

```bash
python analyze_recall.py
```

---

## Key Findings

**LLM menambah nilai nyata di atas rule-based dan ML baseline** — `rule_sus` dan Isolation Forest keduanya dapat recall 1.0 dengan 0 token, tapi F1 mereka 0.500 dan 0.316. LLM baseline mencapai F1 0.667 (+0.167 di atas rule terbaik) karena lebih akurat dalam mengidentifikasi PID mana yang benar-benar malicious.

**`incident_cluster` adalah sweet spot** — satu-satunya strategi yang mempertahankan recall 1.0 sekaligus hemat 62.5% token. F1-nya (0.500) setara dengan rule_sus, artinya LLM dengan compression yang tepat bisa dapat performa rule-based dengan biaya token jauh lebih rendah dari baseline.

**Exact deduplication rentan collision** — `dedup` dan `near_dedup` keduanya miss 1 dari 3 evil PID karena key kolom dari evil PID tersebut sudah diklaim PID lain. Ini limitasi fundamental, bukan bug implementasi.

**`trend_detection` paradox** — summarizing burst events justru merusak konteks yang dibutuhkan LLM. Summary `evt=59 count=50` menghilangkan informasi PID spesifik, sehingga LLM tidak bisa mengidentifikasi malicious process.

**Isolation Forest ROC-AUC 1.0 perlu dikritisi** — hasil ini kemungkinan overfit di subset 1000 baris dengan hanya 15 evil events. Paper Highnam et al. (2021) dengan full dataset mendapat 0.850 — angka yang lebih representatif.

Lihat [FINDINGS.md](./FINDINGS.md) untuk analisis lengkap beserta referensi.

---

## Stack

- **Dataset**: [BETH](https://www.kaggle.com/datasets/katehighnam/beth-dataset) — real Kubernetes honeypot syscall logs
- **LLM**: `llama-3.3-70b-versatile` via [Groq](https://groq.com) (gratis)
- **ML Baseline**: Isolation Forest (scikit-learn) — mengikuti Highnam et al. (2021)
- **Language**: Python 3.10+
- **Libraries**: `pandas`, `groq`, `scikit-learn`, `rich`, `python-dotenv`

## Referensi

1. Highnam et al. (2021) — *BETH Dataset: Real Cybersecurity Data for Unsupervised Anomaly Detection Research.* CEUR-WS Vol-3095. https://ceur-ws.org/Vol-3095/paper1.pdf
2. Eremin (2025) — *Unsupervised Anomaly Detection on Cybersecurity Data Streams: A Case with BETH Dataset.* IJOIT 13(6). https://arxiv.org/pdf/2503.04178
3. Lakha et al. (2022) — *Anomaly Detection in Cybersecurity Events Through GNN and Transformer: A Case Study with BETH Dataset.* IEEE Big Data 2022.
4. Khan et al. (2023) — *Anomaly Detection for BETH Dataset Using Machine Learning Approaches.* IEEE ICECCT 2023.

---

## Keterbatasan

- Eksperimen dilakukan pada subset kecil dataset (1000 baris) karena keterbatasan rate limit API gratis
- Ground truth (`evil` label) di BETH sangat "bersih" — di dunia nyata evil events bisa bercampur dengan benign events dalam satu PID
- Whitelist eventId dikalibrasi manual berdasarkan pengetahuan Linux syscall, bukan data-driven
- Evaluasi hanya pada satu model (llama-3.3-70b) — hasil bisa berbeda di model lain

---

## Lisensi

MIT
