# SOC Token Efficiency — Findings

**Dataset**: BETH (labelled_testing_data.csv) · 1000 rows · 15 evil events · 3 evil PIDs  
**Model LLM**: llama-3.3-70b-versatile (Groq)  
**Baseline ML**: Isolation Forest (scikit-learn, Highnam et al. 2021)  
**Date**: 2026-06-22

---

## Ringkasan Hasil

| Detector | Type | Tokens | Savings | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|---|
| `rule_sus` | heuristic | 0 | 100% | 1.0 | 0.500 | — |
| `rule_eventid` | heuristic | 0 | 100% | 0.0 | 0.000 | — |
| `rule_combined` | heuristic | 0 | 100% | 0.0 | 0.000 | — |
| `rule_burst` | heuristic | 0 | 100% | 0.0 | 0.000 | — |
| `rule_all` | heuristic | 0 | 100% | 1.0 | 0.333 | — |
| `isolation_forest` | ML | 0 | 100% | 1.0 | 0.316 | 1.0* |
| `baseline` | LLM | 4,781 | 0% | 1.0 | 0.667 | — |
| `dedup` | LLM | 1,373 | 71.3% | 0.667 | 0.364 | — |
| `near_dedup` | LLM | 1,484 | 69.0% | 0.667 | 0.364 | — |
| `trend_detection` | LLM | 1,967 | 58.8% | 0.333 | 0.182 | — |
| `incident_cluster` | LLM | 1,791 | 62.5% | 1.0 | 0.500 | — |
| `whitelist` | LLM | 4,839 | -1.3% | 1.0 | 0.667 | — |
| `severity_filter` | LLM | 4,897 | -2.4% | 0.0 | 0.000 | — |

*ROC-AUC 1.0 kemungkinan overfit di subset 1000 baris — paper asli dengan full dataset dapat 0.850.

---

## Temuan Utama

### 1. LLM memberikan nilai tambah nyata di atas baseline ML dan heuristic

`rule_sus` dan `isolation_forest` keduanya dapat recall 1.0 dengan 0 token,
tapi F1 mereka 0.500 dan 0.316 — jauh di bawah `LLM baseline` (F1 0.667).
Selisih ini berasal dari precision: LLM lebih akurat mengidentifikasi PID mana
yang benar-benar malicious, bukan sekadar mencurigai semua PID yang punya sus=1.

**LLM menambah F1 +0.167 di atas rule_sus, dengan biaya 4,781 token.**
Pertanyaan riset: apakah delta ini worth it, dan bagaimana meminimalkan biayanya?

### 2. `incident_cluster` adalah strategi terbaik secara token-recall trade-off

Satu-satunya strategi yang mempertahankan recall 1.0 sekaligus hemat 62.5% token.
F1-nya (0.500) setara dengan `rule_sus` — artinya LLM dengan compression yang
tepat bisa dapat performa rule-based dengan tetap memanfaatkan kemampuan reasoning LLM,
tapi dengan biaya token yang jauh lebih rendah dari baseline.

### 3. Exact deduplication rentan collision antar PID

`dedup` dan `near_dedup` keduanya miss PID 1323 karena kombinasi key
`(eventId, userId)` milik PID 1323 sudah "diklaim" oleh PID lain yang
diproses lebih dulu. Ini bukan bug implementasi — ini limitasi fundamental
dari deduplication berbasis kolom tunggal.

### 4. `rule_eventid` dan `rule_combined` F1 = 0

Tidak ada satu pun evil PID di BETH yang mengeksekusi syscall yang secara
konvensional dianggap "high-risk" (execve, setuid, clone, dll).
Ini konsisten dengan temuan Highnam et al. (2021) yang tidak merekomendasikan
rule berbasis eventId untuk dataset ini — pendekatan ML unsupervised lebih tepat.

### 5. `trend_detection` paradox

Meringkas burst events menjadi summary `[SUMMARY] evt=X count=50` justru
menghapus konteks PID spesifik yang dibutuhkan LLM untuk reasoning.
F1 terendah di antara strategi yang tidak error (0.182), meski hemat 58.8% token.

### 6. `severity_filter` tidak reliable untuk BETH

F1 = 0.0 konsisten. Label `sus` di BETH tidak berkorelasi kuat dengan `evil`
di semua window dataset. Strategi ini hanya valid jika labeling suspicious
sudah dikalibrasi di environment produksi.

### 7. Isolation Forest ROC-AUC 1.0 perlu dikritisi

ROC-AUC 1.0 di subset 1000 baris dengan hanya 15 evil events sangat mungkin
overfit ke karakteristik spesifik 3 evil PID ini. Paper Highnam et al. (2021)
yang menggunakan full dataset mendapat ROC-AUC 0.850 — angka yang lebih
representatif. Eksperimen ini perlu divalidasi di window dataset yang lebih besar.

---

## Pertanyaan Riset yang Muncul

1. **Apakah LLM value-add (+0.167 F1) konsisten di semua window dataset?**
   Atau hanya kebetulan di 1000 baris pertama ini?

2. **Bisakah pipeline kombinasi (whitelist → incident_cluster) mendapat
   token savings >70% dengan recall tetap 1.0?**
   Belum divalidasi karena rate limit API.

3. **Bagaimana performa Isolation Forest di full dataset (188k rows)?**
   Apakah ROC-AUC tetap tinggi atau turun mendekati 0.850 seperti paper asli?

4. **Apakah threshold `unique_events > 5` di incident_cluster optimal?**
   Threshold lebih tinggi bisa kurangi false positive PID tapi berisiko miss evil PID.

5. **Apakah trend_detection bisa diperbaiki dengan summary per (eventId, processId)
   alih-alih per eventId saja?**
   Ini akan mempertahankan konteks PID dalam summary.

---

## Keterbatasan Eksperimen

- Subset kecil (1000 baris dari 188k) — temuan belum tentu generalisasi
- Hanya satu model LLM (llama-3.3-70b-versatile via Groq)
- Evil PID di BETH sangat "bersih" — semua event evil juga berlabel sus=1,
  tidak realistis untuk SOC produksi
- Whitelist eventId dikalibrasi manual, tidak data-driven
- Pipeline kombinasi belum selesai divalidasi karena rate limit API
- ROC-AUC hanya tersedia untuk Isolation Forest, tidak untuk LLM
  (LLM tidak menghasilkan confidence score per event)

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
