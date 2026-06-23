"""
visualize_results.py — Plot semua run dari results/runs/*.json

Membaca semua file JSON (dari main.py maupun run_pipeline.py),
merge hasilnya, dan generate dashboard HTML.

Jalankan: python visualize_results.py
Output  : results/summary.html
"""
import json, os, sys, glob

run_files = sorted(glob.glob("results/runs/*.json"))
if not run_files:
    print("Tidak ada file run ditemukan di results/runs/")
    sys.exit(1)

print(f"Ditemukan {len(run_files)} file:")
for f in run_files:
    print(f"  {f}")

# Merge semua run — strategy/rule terbaru menang
all_metrics: dict[str, dict] = {}
for fpath in run_files:
    with open(fpath) as f:
        entries = json.load(f)
    for m in entries:
        if m.get("error") and m.get("total_tokens", 0) == 0:
            continue
        # Normalize: rule-based pakai field "rule", LLM pakai "strategy"
        name = m.get("strategy") or m.get("rule", "unknown")
        all_metrics[name] = {
            "name"          : name,
            "type"          : "rule" if m.get("rule") and not m.get("input_tokens") else "LLM",
            "total_tokens"  : m.get("total_tokens", 0),
            "token_savings" : m.get("token_savings", 100.0),
            "precision"     : m.get("precision", 0.0),
            "recall"        : m.get("recall", 0.0),
            "f1"            : m.get("f1", 0.0),
            "roc_auc"       : m.get("roc_auc"),
            "log_count"     : m.get("log_count", 0),
            "threat_level"  : m.get("threat_level", "N/A"),
        }

# Urutan tampilan
ORDER = [
    "rule_sus", "rule_eventid", "rule_combined", "rule_burst", "rule_all",
    "isolation_forest",
    "baseline", "dedup", "near_dedup", "severity_filter",
    "trend_detection", "incident_cluster", "whitelist",
    "pipeline_a_wl+cluster", "pipeline_b_wl+cluster+dedup", "pipeline_c_wl+trend+cluster",
]
data = [all_metrics[k] for k in ORDER if k in all_metrics]
# Tambahkan entry yang tidak ada di ORDER
for k, v in all_metrics.items():
    if k not in ORDER:
        data.append(v)

labels_js   = json.dumps([d["name"] for d in data])
tokens_js   = json.dumps([d["total_tokens"] for d in data])
savings_js  = json.dumps([d["token_savings"] for d in data])
f1_js       = json.dumps([d["f1"] for d in data])
recall_js   = json.dumps([d["recall"] for d in data])
precision_js= json.dumps([d["precision"] for d in data])
types_js    = json.dumps([d["type"] for d in data])

html = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>SOC Token Efficiency — Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }}
h1 {{ font-size: 1.4rem; font-weight: 500; margin-bottom: 0.3rem; }}
.sub {{ font-size: 0.82rem; color: #64748b; margin-bottom: 2rem; }}
.grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 2rem; }}
.card {{ background: #1e2433; border-radius: 10px; padding: 1rem; }}
.card .lbl {{ font-size: 11px; color: #64748b; margin-bottom: 4px; }}
.card .val {{ font-size: 20px; font-weight: 500; }}
.card .sub2 {{ font-size: 11px; color: #64748b; margin-top: 2px; }}
.green {{ color: #34d399; }} .amber {{ color: #fbbf24; }} .blue {{ color: #60a5fa; }} .red {{ color: #f87171; }}
.wrap {{ background: #1e2433; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }}
.wrap h2 {{ font-size: 0.85rem; font-weight: 500; color: #94a3b8; margin-bottom: 1rem; }}
canvas {{ max-height: 300px; }}
.legend {{ display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 10px; font-size: 12px; color: #64748b; }}
.legend span {{ display: flex; align-items: center; gap: 5px; }}
.dot {{ width: 10px; height: 10px; border-radius: 2px; display: inline-block; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
th {{ background: #2d3748; color: #94a3b8; text-align: left; padding: 7px 10px; font-weight: 500; }}
td {{ padding: 6px 10px; border-top: 1px solid #2d3748; }}
tr:hover td {{ background: #253048; }}
.g {{ color: #34d399; font-weight: 500; }}
.a {{ color: #fbbf24; }}
.r {{ color: #f87171; }}
.badge {{ font-size: 10px; padding: 2px 6px; border-radius: 4px; }}
.badge-rule {{ background: #534AB720; color: #A09BED; }}
.badge-llm  {{ background: #185FA520; color: #60a5fa; }}
</style>
</head>
<body>
<h1>SOC Token Efficiency — Dashboard</h1>
<p class="sub">BETH dataset · labelled_testing_data · {len(data)} detectors/strategies</p>

<div class="grid">
  <div class="card">
    <div class="lbl">Best F1 (no LLM)</div>
    <div class="val blue" id="c1">—</div>
    <div class="sub2" id="c1s">—</div>
  </div>
  <div class="card">
    <div class="lbl">Best F1 (LLM)</div>
    <div class="val green" id="c2">—</div>
    <div class="sub2" id="c2s">—</div>
  </div>
  <div class="card">
    <div class="lbl">Best pipeline savings</div>
    <div class="val green" id="c3">—</div>
    <div class="sub2" id="c3s">—</div>
  </div>
  <div class="card">
    <div class="lbl">LLM value-add (F1)</div>
    <div class="val amber" id="c4">—</div>
    <div class="sub2">vs best rule-based</div>
  </div>
</div>

<div class="legend">
  <span><span class="dot" style="background:#534AB7"></span>Heuristic rule (0 token)</span>
  <span><span class="dot" style="background:#0F6E56"></span>Isolation Forest (0 token)</span>
  <span><span class="dot" style="background:#185FA5"></span>LLM single strategy</span>
  <span><span class="dot" style="background:#1D9E75"></span>LLM pipeline</span>
  <span><span style="border-bottom:2px dashed #34d399;width:16px;display:inline-block"></span>Recall</span>
</div>

<div class="wrap">
  <h2>F1 score per detector/strategy</h2>
  <div style="position:relative;width:100%;height:300px;"><canvas id="f1Chart" role="img" aria-label="F1 score comparison across all detectors and strategies"></canvas></div>
</div>

<div class="wrap">
  <h2>Token usage</h2>
  <div style="position:relative;width:100%;height:220px;"><canvas id="tokChart" role="img" aria-label="Token usage per strategy, rule-based use 0 tokens"></canvas></div>
</div>

<div class="wrap">
  <h2>Token savings (%)</h2>
  <div style="position:relative;width:100%;height:200px;"><canvas id="savChart" role="img" aria-label="Token savings percentage per strategy"></canvas></div>
</div>

<div class="wrap">
  <h2>Precision · Recall · F1</h2>
  <div style="position:relative;width:100%;height:280px;"><canvas id="prfChart" role="img" aria-label="Precision recall F1 breakdown per strategy"></canvas></div>
</div>

<div class="wrap">
  <h2>Full results table</h2>
  <table>
    <thead>
      <tr><th>Strategy</th><th>Type</th><th>Logs</th><th>Tokens</th><th>Savings</th><th>Precision</th><th>Recall</th><th>F1</th><th>ROC-AUC</th></tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
</div>

<script>
const labels    = {labels_js};
const tokens    = {tokens_js};
const savings   = {savings_js};
const f1        = {f1_js};
const recall    = {recall_js};
const precision = {precision_js};
const types     = {types_js};
const data_raw  = {json.dumps(data)};

function barColor(i) {{
  const n = labels[i];
  if (n === 'isolation_forest') return 'rgba(15,110,86,0.8)';
  if (types[i] === 'rule')       return 'rgba(83,74,183,0.75)';
  if (n.startsWith('pipeline'))  return 'rgba(29,158,117,0.75)';
  return 'rgba(24,95,165,0.75)';
}}
const bg = labels.map((_,i) => barColor(i));

// Stat cards
const ruleF1 = data_raw.filter(d => d.type === 'rule').map(d => d.f1);
const llmF1  = data_raw.filter(d => d.type !== 'rule').map(d => d.f1);
const bestRule = Math.max(...ruleF1);
const bestLLM  = Math.max(...llmF1);
const bestRuleName = data_raw.find(d => d.f1 === bestRule && d.type === 'rule')?.name || '—';
const bestLLMName  = data_raw.find(d => d.f1 === bestLLM  && d.type !== 'rule')?.name || '—';

const pipelines = data_raw.filter(d => d.name.startsWith('pipeline'));
const bestPipeSav = pipelines.length ? Math.max(...pipelines.map(d => d.token_savings)) : 0;
const bestPipeName = pipelines.find(d => d.token_savings === bestPipeSav)?.name || '—';

document.getElementById('c1').textContent  = bestRule.toFixed(3);
document.getElementById('c1s').textContent = bestRuleName;
document.getElementById('c2').textContent  = bestLLM.toFixed(3);
document.getElementById('c2s').textContent = bestLLMName;
document.getElementById('c3').textContent  = bestPipeSav.toFixed(1) + '%';
document.getElementById('c3s').textContent = bestPipeName;
document.getElementById('c4').textContent  = '+' + (bestLLM - bestRule).toFixed(3);

const GRID = 'rgba(128,128,128,0.1)';
const TICK = {{ color: '#64748b', font: {{ size: 10 }} }};
const TICKX = {{ color: '#94a3b8', font: {{ size: 9 }}, maxRotation: 45 }};

new Chart(document.getElementById('f1Chart'), {{
  type: 'bar',
  data: {{ labels, datasets: [
    {{ label: 'F1', data: f1, backgroundColor: bg, borderWidth: 0, yAxisID: 'y' }},
    {{ label: 'Recall', data: recall, type: 'line', borderColor: '#34d399', borderWidth: 2,
       borderDash: [5,3], pointBackgroundColor: '#34d399', pointRadius: 3,
       fill: false, yAxisID: 'y', tension: 0, spanGaps: true }}
  ]}},
  options: {{ responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ y: {{ min:0, max:1, ticks: TICK, grid: {{ color: GRID }} }}, x: {{ ticks: TICKX, grid: {{ display: false }} }} }}
  }}
}});

new Chart(document.getElementById('tokChart'), {{
  type: 'bar',
  data: {{ labels, datasets: [{{ label: 'Tokens', data: tokens, backgroundColor: bg, borderWidth: 0 }}] }},
  options: {{ responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ y: {{ ticks: {{ ...TICK, callback: v => v >= 1000 ? (v/1000).toFixed(1)+'k' : v }}, grid: {{ color: GRID }} }}, x: {{ ticks: TICKX, grid: {{ display: false }} }} }}
  }}
}});

new Chart(document.getElementById('savChart'), {{
  type: 'bar',
  data: {{ labels, datasets: [{{ label: 'Savings %', data: savings,
    backgroundColor: savings.map(v => v > 60 ? 'rgba(29,158,117,0.75)' : v > 0 ? 'rgba(24,95,165,0.6)' : 'rgba(226,75,74,0.6)'),
    borderWidth: 0 }}] }},
  options: {{ responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ y: {{ ticks: {{ ...TICK, callback: v => v+'%' }}, grid: {{ color: GRID }} }}, x: {{ ticks: TICKX, grid: {{ display: false }} }} }}
  }}
}});

new Chart(document.getElementById('prfChart'), {{
  type: 'bar',
  data: {{ labels, datasets: [
    {{ label: 'Precision', data: precision, backgroundColor: 'rgba(96,165,250,0.7)', borderWidth: 0 }},
    {{ label: 'Recall',    data: recall,    backgroundColor: 'rgba(52,211,153,0.7)', borderWidth: 0 }},
    {{ label: 'F1',        data: f1,        backgroundColor: 'rgba(251,191,36,0.7)',  borderWidth: 0 }},
  ]}},
  options: {{ responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }},
    scales: {{ y: {{ min:0, max:1, ticks: TICK, grid: {{ color: GRID }} }}, x: {{ ticks: TICKX, grid: {{ display: false }} }} }}
  }}
}});

// Table
const tbody = document.getElementById('tbody');
const maxF1v = Math.max(...f1);
data_raw.forEach(d => {{
  const isB = d.f1 === maxF1v;
  const tr = document.createElement('tr');
  const rocStr = d.roc_auc != null ? d.roc_auc.toFixed(3) : '—';
  const savCls = d.token_savings > 60 ? 'g' : d.token_savings < 0 ? 'r' : '';
  const f1Cls  = d.f1 >= 0.5 ? 'g' : d.f1 > 0 ? 'a' : 'r';
  const badge  = d.type === 'rule'
    ? '<span class="badge badge-rule">rule</span>'
    : '<span class="badge badge-llm">LLM</span>';
  tr.innerHTML = `
    <td>${{d.name}}</td>
    <td>${{badge}}</td>
    <td>${{d.log_count || '—'}}</td>
    <td>${{d.total_tokens.toLocaleString()}}</td>
    <td class="${{savCls}}">${{d.token_savings.toFixed(1)}}%</td>
    <td>${{d.precision.toFixed(3)}}</td>
    <td>${{d.recall.toFixed(3)}}</td>
    <td class="${{f1Cls}}">${{d.f1.toFixed(3)}}</td>
    <td>${{rocStr}}</td>
  `;
  tbody.appendChild(tr);
}});
</script>
</body>
</html>"""

os.makedirs("results", exist_ok=True)
with open("results/summary.html", "w", encoding="utf-8") as f:
    f.write(html)

print(f"\nDone! {len(data)} entries diplot.")
print("Buka: results/summary.html")