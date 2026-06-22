"""
visualize_results.py — Plot semua run dari results/runs/*.json

Jalankan: python visualize_results.py
Output  : results/summary.html (buka di browser)
"""
import json, os, sys, glob
from collections import defaultdict

# --- Load semua run JSON ---
run_files = sorted(glob.glob("results/runs/run_*.json"))
if not run_files:
    print("Tidak ada file run ditemukan di results/runs/")
    sys.exit(1)

print(f"Ditemukan {len(run_files)} run file:")
for f in run_files:
    print(f"  {f}")

# Gabung semua run, deduplicate per strategy (ambil run terbaru)
all_metrics: dict[str, dict] = {}
for fpath in run_files:
    with open(fpath) as f:
        metrics = json.load(f)
    for m in metrics:
        if m.get("error"):
            continue
        name = m["strategy"]
        # Override dengan run terbaru (file sudah sorted ascending)
        all_metrics[name] = m

strategies = list(all_metrics.keys())
data       = list(all_metrics.values())

# --- Build HTML ---
labels_js   = json.dumps(strategies)
tokens_js   = json.dumps([d["total_tokens"] for d in data])
savings_js  = json.dumps([d["token_savings"] for d in data])
f1_js       = json.dumps([d["f1"] for d in data])
recall_js   = json.dumps([d["recall"] for d in data])
precision_js= json.dumps([d["precision"] for d in data])
logs_js     = json.dumps([d["log_count"] for d in data])

html = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>SOC Token Efficiency — Results</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }}
  h1 {{ font-size: 1.4rem; font-weight: 500; margin-bottom: 0.4rem; color: #f8fafc; }}
  .subtitle {{ font-size: 0.85rem; color: #64748b; margin-bottom: 2rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: #1e2433; border-radius: 10px; padding: 1.2rem; }}
  .card .label {{ font-size: 0.75rem; color: #64748b; margin-bottom: 0.3rem; }}
  .card .value {{ font-size: 1.6rem; font-weight: 500; }}
  .green {{ color: #34d399; }}
  .amber {{ color: #fbbf24; }}
  .blue  {{ color: #60a5fa; }}
  .chart-wrap {{ background: #1e2433; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .chart-wrap h2 {{ font-size: 0.9rem; font-weight: 500; color: #94a3b8; margin-bottom: 1rem; }}
  canvas {{ max-height: 280px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; background: #1e2433; border-radius: 10px; overflow: hidden; }}
  th {{ background: #2d3748; color: #94a3b8; text-align: left; padding: 0.6rem 1rem; font-weight: 500; }}
  td {{ padding: 0.55rem 1rem; border-top: 1px solid #2d3748; }}
  tr:hover td {{ background: #253048; }}
  .best {{ color: #34d399; font-weight: 500; }}
  .zero {{ color: #ef4444; }}
</style>
</head>
<body>
<h1>SOC Token Efficiency — Experiment Results</h1>
<p class="subtitle">BETH dataset · labelled_testing_data · {len(strategies)} strategies evaluated</p>

<div class="grid">
  <div class="card">
    <div class="label">Best F1 score</div>
    <div class="value blue" id="bestF1">—</div>
  </div>
  <div class="card">
    <div class="label">Max token savings</div>
    <div class="value green" id="maxSavings">—</div>
  </div>
  <div class="card">
    <div class="label">Strategies evaluated</div>
    <div class="value amber">{len(strategies)}</div>
  </div>
</div>

<div class="chart-wrap">
  <h2>Token usage vs F1 score per strategy</h2>
  <canvas id="mainChart"></canvas>
</div>

<div class="chart-wrap">
  <h2>Token savings (%)</h2>
  <canvas id="savingsChart"></canvas>
</div>

<div class="chart-wrap">
  <h2>Precision · Recall · F1 breakdown</h2>
  <canvas id="prf1Chart"></canvas>
</div>

<div class="chart-wrap">
  <h2>Logs sent to LLM per strategy</h2>
  <canvas id="logsChart"></canvas>
</div>

<div class="chart-wrap">
  <h2>Full results table</h2>
  <table>
    <thead>
      <tr>
        <th>Strategy</th><th>Logs sent</th><th>Total tokens</th>
        <th>Savings</th><th>Precision</th><th>Recall</th><th>F1</th><th>Threat level</th>
      </tr>
    </thead>
    <tbody id="tableBody"></tbody>
  </table>
</div>

<script>
const labels    = {labels_js};
const tokens    = {tokens_js};
const savings   = {savings_js};
const f1        = {f1_js};
const recall    = {recall_js};
const precision = {precision_js};
const logCounts = {logs_js};
const data_raw  = {json.dumps(data)};

// Fill stat cards
const maxF1  = Math.max(...f1);
const maxSav = Math.max(...savings);
document.getElementById('bestF1').textContent = maxF1.toFixed(3);
document.getElementById('maxSavings').textContent = maxSav.toFixed(1) + '%';

const BAR_BLUE  = 'rgba(96,165,250,0.7)';
const BAR_GREEN = 'rgba(52,211,153,0.7)';
const BAR_AMBER = 'rgba(251,191,36,0.7)';
const BAR_RED   = 'rgba(239,68,68,0.6)';
const BAR_GRAY  = 'rgba(100,116,139,0.5)';

const savingColors = savings.map(v => v > 50 ? BAR_GREEN : v > 0 ? BAR_BLUE : BAR_RED);

// Chart 1: tokens + F1 line
new Chart(document.getElementById('mainChart'), {{
  type: 'bar',
  data: {{
    labels,
    datasets: [
      {{ label: 'Total tokens', data: tokens, backgroundColor: BAR_BLUE, yAxisID: 'yTok' }},
      {{ label: 'F1 score', data: f1, type: 'line', borderColor: '#34d399',
         backgroundColor: 'transparent', pointBackgroundColor: f1.map(v => v >= 0.5 ? '#34d399' : v > 0 ? '#fbbf24' : '#ef4444'),
         pointRadius: 6, borderWidth: 2, yAxisID: 'yF1', tension: 0.3 }}
    ]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }},
    scales: {{
      yTok: {{ position: 'left',  ticks: {{ color: '#64748b', callback: v => v >= 1000 ? (v/1000).toFixed(1)+'k' : v }} , grid: {{ color: '#2d3748' }} }},
      yF1:  {{ position: 'right', min: 0, max: 1, ticks: {{ color: '#64748b' }}, grid: {{ display: false }} }},
      x:    {{ ticks: {{ color: '#94a3b8', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
    }}
  }}
}});

// Chart 2: savings
new Chart(document.getElementById('savingsChart'), {{
  type: 'bar',
  data: {{ labels, datasets: [{{ label: 'Token savings %', data: savings, backgroundColor: savingColors }}] }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      y: {{ ticks: {{ color: '#64748b', callback: v => v+'%' }}, grid: {{ color: '#2d3748' }} }},
      x: {{ ticks: {{ color: '#94a3b8', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
    }}
  }}
}});

// Chart 3: P/R/F1
new Chart(document.getElementById('prf1Chart'), {{
  type: 'bar',
  data: {{
    labels,
    datasets: [
      {{ label: 'Precision', data: precision, backgroundColor: 'rgba(96,165,250,0.7)' }},
      {{ label: 'Recall',    data: recall,    backgroundColor: 'rgba(52,211,153,0.7)' }},
      {{ label: 'F1',        data: f1,        backgroundColor: 'rgba(251,191,36,0.7)' }},
    ]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }},
    scales: {{
      y: {{ min: 0, max: 1, ticks: {{ color: '#64748b' }}, grid: {{ color: '#2d3748' }} }},
      x: {{ ticks: {{ color: '#94a3b8', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
    }}
  }}
}});

// Chart 4: log counts
new Chart(document.getElementById('logsChart'), {{
  type: 'bar',
  data: {{ labels, datasets: [{{ label: 'Logs sent', data: logCounts, backgroundColor: BAR_GRAY }}] }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      y: {{ ticks: {{ color: '#64748b' }}, grid: {{ color: '#2d3748' }} }},
      x: {{ ticks: {{ color: '#94a3b8', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
    }}
  }}
}});

// Table
const tbody = document.getElementById('tableBody');
const maxF1Val = Math.max(...f1);
data_raw.forEach(d => {{
  const isMaxF1  = d.f1 === maxF1Val;
  const isBestSav= d.token_savings === Math.max(...savings);
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td>${{d.strategy}}</td>
    <td>${{d.log_count}}</td>
    <td>${{d.total_tokens.toLocaleString()}}</td>
    <td class="${{d.token_savings > 50 ? 'best' : d.token_savings < 0 ? 'zero' : ''}}">${{d.token_savings.toFixed(1)}}%</td>
    <td>${{d.precision.toFixed(3)}}</td>
    <td>${{d.recall.toFixed(3)}}</td>
    <td class="${{isMaxF1 ? 'best' : d.f1 === 0 ? 'zero' : ''}}">${{d.f1.toFixed(3)}}</td>
    <td>${{d.threat_level}}</td>
  `;
  tbody.appendChild(tr);
}});
</script>
</body>
</html>"""

os.makedirs("results", exist_ok=True)
with open("results/summary.html", "w", encoding="utf-8") as f:
    f.write(html)

print("\nDone! Buka: results/summary.html")
