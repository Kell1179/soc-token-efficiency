# SOC Token Efficiency — Findings

**Dataset**: BETH (labelled_testing_data.csv) · 1000 rows · 15 evil events · 3 evil PIDs  
**Model LLM**: llama-3.3-70b-versatile (Groq)  
**Baseline ML**: Isolation Forest (scikit-learn, Highnam et al. 2021)  
**Date**: 2026-06-22 — 2026-06-23

---

## Ringkasan Hasil

### Baseline (rule-based + ML)

| Detector | Type | Tokens | Savings | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|---|
| `rule_sus` | heuristic | 0 | 100% | 1.0 | 0.500 | — |
| `rule_eventid` | heuristic | 0 | 100% | 0.0 | 0.000 | — |
| `rule_combined` | heuristic | 0 | 100% | 0.0 | 0.000 | — |
| `rule_burst` | heuristic | 0 | 100% | 0.0 | 0.000 | — |
| `rule_all` | heuristic | 0 | 100% | 1.0 | 0.333 | — |
| `isolation_forest` | ML | 0 | 100% | 1.0 | 0.316 | 1.0* |

### LLM — strategi tunggal

| Strategy | Type | Tokens | Savings | Recall | F1 |
|---|---|---|---|---|---|
| `baseline` | LLM | 4,785 | 0% | 1.0 | 0.667 |
| `dedup` | LLM | 1,372 | 71.3% | 0.667 | 0.364 |
| `near_dedup` | LLM | 1,490 | 68.9% | 0.667 | 0.364 |
| `trend_detection` | LLM | 1,971 | 58.8% | 0.333 | 0.167 |
| `incident_cluster` | LLM | 1,798 | 62.4% | 1.0 | 0.500 |
| `whitelist` | LLM | 4,839 | -1.1% | 1.0 | 0.667 |
| `severity_filter` | LLM | 4,897 | -2.3% | 0.0 | 0.000 |

### LLM — pipeline kombinasi

| Strategy | Type | Tokens | Savings | Recall | F1 |
|---|---|---|---|---|---|
| `pipeline_a` (wl→cluster) | LLM pipeline | 1,456 | 69.6% | **1.0** | 0.500 |
| `pipeline_b` (wl→cluster→dedup) | LLM pipeline | 596 | **87.5%** | 0.333 | 0.250 |
| `pipeline_c` (wl→trend→cluster) | LLM pipeline | 1,132 | 76.3% | 0.333 | 0.200 |

*ROC-AUC 1.0 kemungkinan overfit di subset 1000 baris — paper asli dengan full dataset dapat 0.850.

---

## Temuan Utama

### 1. LLM memberikan nilai tambah nyata di atas baseline ML dan heuristic

`rule_sus` dan `isolation_forest` keduanya dapat recall 1.0 dengan 0 token,
tapi F1 mereka 0.500 dan 0.316 — jauh di bawah `LLM baseline` (F1 0.667).
Selisih ini berasal dari precision: LLM lebih akurat mengidentifikasi PID mana
yang benar-benar malicious, bukan sekadar mencurigai semua PID yang punya sus=1.

**LLM menambah F1 +0.167 di atas rule_sus terbaik, dengan biaya 4,785 token.**

### 2. `pipeline_a` adalah rekomendasi arsitektur terbaik

`pipeline_a` (whitelist → incident_cluster) adalah sweet spot dari seluruh eksperimen:
- Token savings **69.6%** dari baseline
- Recall **1.0** — tidak ada evil PID yang terlewat
- F1 0.500 — turun 0.167 dari baseline tapi setara dengan rule_sus

Dibanding `incident_cluster` saja (62.4% savings), whitelist di tahap pertama
menambah 7.2% savings tambahan tanpa mengorbankan recall. Ini menunjukkan
bahwa pipeline berlapis lebih efektif dari strategi tunggal.

### 3. Ada titik kritis saat menambah dedup ke pipeline

`pipeline_b` menambahkan dedup setelah cluster dan mendapat savings 87.5%,
tapi recall drop drastis dari 1.0 ke 0.333 — miss 2 dari 3 evil PID.
Penambahan satu tahap compression mengubah pipeline dari recall-safe menjadi recall-unsafe.

Ini implikasi penting untuk desain pipeline SOC: **setiap tahap compression
harus divalidasi dampaknya terhadap recall secara independen**, tidak bisa
diasumsikan bahwa menambah tahap selalu aman.

### 4. Exact deduplication rentan collision antar PID

`dedup`, `near_dedup`, dan `pipeline_b` semuanya miss PID 1323 karena kombinasi
key `(eventId, userId)` milik PID 1323 sudah diklaim oleh PID lain yang diproses
lebih dulu. Ini limitasi fundamental dari deduplication berbasis key kolom.

### 5. `trend_detection` paradox

Meringkas burst events menjadi summary `[SUMMARY] evt=X count=50` menghapus
konteks PID spesifik yang dibutuhkan LLM untuk reasoning. F1 terendah di antara
strategi yang berhasil (0.167), meski hemat 58.8% token. `pipeline_c` yang
menambahkan cluster setelah trend juga tidak membantu — recall tetap 0.333.

### 6. `rule_eventid` dan `rule_combined` F1 = 0

Tidak ada satu pun evil PID di BETH yang mengeksekusi syscall yang secara
konvensional dianggap "high-risk" (execve, setuid, clone, dll). Ini konsisten
dengan Highnam et al. (2021) yang tidak merekomendasikan rule berbasis eventId
untuk dataset ini — pendekatan ML unsupervised lebih tepat.

### 7. `severity_filter` tidak reliable untuk BETH

F1 = 0.0 konsisten. Label `sus` di BETH tidak berkorelasi kuat dengan `evil`.
Strategi ini hanya valid di environment SOC produksi dengan SIEM yang sudah
dikalibrasi.

### 8. Isolation Forest ROC-AUC 1.0 perlu dikritisi

ROC-AUC 1.0 di subset 1000 baris dengan hanya 15 evil events sangat mungkin
overfit. Paper Highnam et al. (2021) dengan full dataset dapat 0.850.

---

## Pertanyaan Riset yang Muncul

1. **Apakah LLM value-add (+0.167 F1) konsisten di semua window dataset?**
   Atau hanya kebetulan di 1000 baris pertama ini?

2. **Apakah pipeline_a recall 1.0 konsisten di window dataset yang berbeda?**
   Perlu divalidasi dengan `--skip 5000`, `--skip 10000`, dll.

3. **Bagaimana performa Isolation Forest di full dataset (188k rows)?**
   Apakah ROC-AUC tetap tinggi atau turun mendekati 0.850 seperti paper asli?

4. **Apakah threshold `unique_events > 5` di incident_cluster optimal?**
   Threshold lebih tinggi bisa kurangi false positive PID tapi berisiko miss evil PID.

5. **Apakah trend_detection bisa diperbaiki dengan summary per (eventId, processId)?**
   Ini akan mempertahankan konteks PID dalam summary alih-alih menghilangkannya.

6. **Apakah pipeline_a tetap recall 1.0 jika evil events tidak selalu berlabel sus=1?**
   Di BETH, semua evil events kebetulan berlabel sus=1. Di dataset lain atau
   produksi, asumsi ini mungkin tidak berlaku.

---

## Keterbatasan Eksperimen

- Subset kecil (1000 baris dari 188k) — temuan belum tentu generalisasi
- Hanya satu model LLM (llama-3.3-70b-versatile via Groq)
- Evil PID di BETH sangat "bersih" — semua event evil berlabel sus=1,
  tidak realistis untuk SOC produksi di mana evil events bisa bercampur
  dengan benign events dalam satu PID
- Whitelist eventId dikalibrasi manual, tidak data-driven
- ROC-AUC hanya tersedia untuk Isolation Forest, tidak untuk LLM
  (LLM tidak menghasilkan confidence score per event)
- Rate limit Groq free tier (100k token/hari) membatasi jumlah run

---

## Referensi

1. Highnam, K., Arulkumaran, K., Hanif, Z., & Jennings, N. R. (2021).
   *BETH dataset: Real cybersecurity data for unsupervised anomaly detection research.*
   CEUR Workshop Proceedings, Vol. 3095.
   https://ceur-ws.org/Vol-3095/paper1.pdf

2. Eremin, E. O. (2025).
   *Unsupervised anomaly detection on cybersecurity data streams: a case with BETH dataset.*
   International Journal of Open Information Technologies, 13(6), 107–113.
   https://arxiv.org/pdf/2503.04178

3. Lakha, B., Mount, S. L., Serra, E., & Cuzzocrea, A. (2022).
   *Anomaly detection in cybersecurity events through graph neural network and
   transformer based model: A case study with BETH dataset.*
   IEEE International Conference on Big Data, 5756–5764.

4. Khan, L. P., Hossain, A., & Dey, S. (2023).
   *Anomaly detection for BETH dataset using machine learning approaches.*
   IEEE ICECCT 2023.
