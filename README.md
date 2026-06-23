# SOC Token Efficiency

Eksperimen untuk mengukur trade-off antara **token compression** dan **detection quality** pada pipeline AI-integrated Security Operations Center (SOC).

Pipeline ini mensimulasikan alur SOC alert: log dari dataset BETH (real Kubernetes honeypot) dikompresi dengan berbagai strategi sebelum dikirim ke LLM, lalu kualitas deteksinya diukur menggunakan precision, recall, dan F1 — dibandingkan terhadap baseline heuristic dan Isolation Forest tanpa LLM.

---

## Latar Belakang

Salah satu barrier terbesar dalam SOC automation berbasis LLM adalah **volume log yang sangat besar**. Sebuah Kubernetes cluster produksi bisa menghasilkan ratusan ribu events per jam — mengirim semuanya ke LLM bukan hanya mahal, tapi seringkali melampaui context window model.

Project ini mengeksplorasi pertanyaan: **seberapa banyak log bisa dikompresi sebelum LLM kehilangan kemampuan mendeteksi ancaman? Dan apakah LLM benar-benar memberikan nilai tambah di atas rule-based detection?**

---

## Demo

```
# Baseline (tanpa compression)
baseline              1000 logs  →  4785 tokens  |  F1: 0.667  Recall: 1.0    (0%)

# Strategi tunggal
dedup                   48 logs  →  1372 tokens  |  F1: 0.364  Recall: 0.667  (-71.3%)
incident_cluster        65 logs  →  1798 tokens  |  F1: 0.500  Recall: 1.0    (-62.4%)
trend_detection         74 logs  →  1971 tokens  |  F1: 0.167  Recall: 0.333  (-58.8%)

# Pipeline kombinasi
pipeline_a (wl+cluster) 50 logs  →  1456 tokens  |  F1: 0.500  Recall: 1.0    (-69.6%) ← sweet spot
pipeline_b (wl+cl+dedup)14 logs  →   596 tokens  |  F1: 0.250  Recall: 0.333  (-87.5%)
pipeline_c (wl+tr+cl)   37 logs  →  1132 tokens  |  F1: 0.200  Recall: 0.333  (-76.3%)

# Baseline tanpa LLM
rule_sus                 —  logs  →     0 tokens  |  F1: 0.500  Recall: 1.0    (-100%)
isolation_forest         —  logs  →     0 tokens  |  F1: 0.316  Recall: 1.0    (-100%)  ROC-AUC: 1.0*
```

*ROC-AUC 1.0 kemungkinan overfit di subset kecil — paper asli dapat 0.850 di full dataset.

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
│   ├── evaluator.py              # Hitung token savings, precision, recall, F1
│   └── detector.py               # Rule-based + Isolation Forest baseline (tanpa LLM)
├── results/
│   └── runs/                     # Output JSON per eksperimen (auto-generated)
├── main.py                       # Eksperimen penuh: semua strategi + baseline
├── run_pipeline.py               # Eksperimen khusus pipeline kombinasi
├── analyze_recall.py             # Deep-dive analisis recall per strategi
├── visualize_results.py          # Generate dashboard HTML dari hasil run
├── FINDINGS.md                   # Dokumentasi temuan eksperimen
├── requirements.txt
└── .env.example
```

---

## Strategi Compression

| Strategi | Cara kerja | Savings | Recall |
|---|---|---|---|
| `baseline` | Semua log dikirim tanpa filter | 0% | 1.0 |
| `dedup` | Hapus duplikat `(eventId, userId)` | ~71% | 0.667 |
| `near_dedup` | Hapus duplikat `(eventId, userId, ret_bucket)` | ~69% | 0.667 |
| `severity_filter` | Hanya kirim log `sus=1` | ~0%* | 0.0* |
| `trend_detection` | Burst events >10x diganti summary count | ~59% | 0.333 |
| `incident_cluster` | Grouping per PID, hanya PID anomalous | ~62% | 1.0 |
| `whitelist` | Buang syscall known-benign kecuali yang flagged | ~0%* | 1.0 |
| `pipeline_a` | whitelist → incident_cluster | ~70% | 1.0 |
| `pipeline_b` | whitelist → incident_cluster → dedup | ~88% | 0.333 |
| `pipeline_c` | whitelist → trend_detection → incident_cluster | ~76% | 0.333 |

*dataset-dependent

## Baseline Tanpa LLM

| Detector | Cara kerja | Tokens | Recall | F1 |
|---|---|---|---|---|
| `rule_sus` | Flag PID yang punya sus=1 | 0 | 1.0 | 0.500 |
| `rule_eventid` | Flag PID yang eksekusi syscall high-risk | 0 | 0.0 | 0.000 |
| `rule_burst` | Flag PID dengan aktivitas burst | 0 | 0.0 | 0.000 |
| `rule_all` | Union semua rule | 0 | 1.0 | 0.333 |
| `isolation_forest` | Anomaly detection (Highnam et al. 2021) | 0 | 1.0 | 0.316 |

---

## Quickstart

### 1. Clone & install

```bash
git clone https://github.com/Kell1179/soc-token-efficiency.git
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
# Eksperimen penuh: semua strategi + rule-based baseline
python main.py --data data/raw/labelled_testing_data.csv

# Hanya pipeline kombinasi (hemat token API)
python run_pipeline.py --data data/raw/labelled_testing_data.csv

# Custom rows dan max logs
python main.py --data data/raw/labelled_testing_data.csv --rows 2000 --max-logs 150

# Skip N baris untuk eksplor window dataset yang berbeda
python main.py --data data/raw/labelled_testing_data.csv --skip 5000 --rows 1000
```

### 5. Rule-based baseline saja (tanpa API)

```bash
# Tidak butuh GROQ_API_KEY
python src/detector.py
```

### 6. Visualisasi hasil

```bash
python visualize_results.py
# Buka results/summary.html di browser
```

### 7. Analisis mendalam

```bash
python analyze_recall.py
```

---

## Key Findings

**`pipeline_a` adalah rekomendasi arsitektur terbaik** — whitelist → incident_cluster menghemat 69.6% token dengan recall tetap 1.0. Tidak ada evil PID yang terlewat, dengan biaya F1 turun dari 0.667 ke 0.500 dibanding baseline.

**LLM menambah nilai nyata di atas rule-based** — `rule_sus` dan Isolation Forest dapat recall 1.0 dengan 0 token, tapi F1-nya hanya 0.500 dan 0.316. LLM baseline mencapai F1 0.667 (+0.167) karena lebih akurat membedakan PID yang benar-benar malicious dari yang sekadar suspicious.

**Ada titik kritis saat menambah dedup ke pipeline** — `pipeline_b` menambahkan dedup setelah cluster dan savings melonjak ke 87.5%, tapi recall drop dari 1.0 ke 0.333. Satu tahap compression tambahan bisa mengubah pipeline dari recall-safe menjadi recall-unsafe.

**Exact deduplication rentan collision** — `dedup` dan `near_dedup` miss 1 dari 3 evil PID karena key kolom dari evil PID tersebut sudah diklaim PID lain. Limitasi fundamental, bukan bug.

**`trend_detection` paradox** — summarizing burst events menghapus konteks PID spesifik yang dibutuhkan LLM. F1 terendah (0.167) meski hemat 58.8% token.

Lihat [FINDINGS.md](./FINDINGS.md) untuk analisis lengkap beserta referensi.

---

## Stack

- **Dataset**: [BETH](https://www.kaggle.com/datasets/katehighnam/beth-dataset) — real Kubernetes honeypot syscall logs
- **LLM**: `llama-3.3-70b-versatile` via [Groq](https://groq.com) (gratis)
- **ML Baseline**: Isolation Forest (scikit-learn) — mengikuti Highnam et al. (2021)
- **Language**: Python 3.10+
- **Libraries**: `pandas`, `groq`, `scikit-learn`, `rich`, `python-dotenv`

---

## Referensi

1. Highnam et al. (2021) — *BETH Dataset: Real Cybersecurity Data for Unsupervised Anomaly Detection Research.* CEUR-WS Vol-3095. https://ceur-ws.org/Vol-3095/paper1.pdf
2. Eremin (2025) — *Unsupervised Anomaly Detection on Cybersecurity Data Streams: A Case with BETH Dataset.* IJOIT 13(6). https://arxiv.org/pdf/2503.04178
3. Lakha et al. (2022) — *Anomaly Detection in Cybersecurity Events Through GNN and Transformer: A Case Study with BETH Dataset.* IEEE Big Data 2022.
4. Khan et al. (2023) — *Anomaly Detection for BETH Dataset Using Machine Learning Approaches.* IEEE ICECCT 2023.

---

## Keterbatasan

- Eksperimen dilakukan pada subset kecil (1000 baris dari 188k) karena rate limit API gratis
- Evil PID di BETH sangat "bersih" — semua event evil berlabel sus=1, tidak realistis untuk SOC produksi
- Whitelist eventId dikalibrasi manual, tidak data-driven
- Evaluasi hanya pada satu model (llama-3.3-70b) — hasil bisa berbeda di model lain
- ROC-AUC hanya tersedia untuk Isolation Forest, tidak untuk LLM

---

## Lisensi

MIT