#!/usr/bin/env python3
"""Render comparison.json → comparison.html (self-contained dashboard).

Pico.css + Chart.js loaded via CDN. No build step. The HTML is intended to be
opened directly from a GitHub Actions artifact download by a non-technical
reviewer (the Director of CICD), so everything ships in one file.

Usage:
    python render_html.py --input ./out/comparison.json --output ./out/comparison.html
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from textwrap import dedent


HTML_TEMPLATE = dedent(
    """\
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>IaC Security Bake-Off Results</title>
      <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css" />
      <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
      <style>
        main { max-width: 1200px; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
        @media (max-width: 800px) { .grid-2 { grid-template-columns: 1fr; } }
        canvas { max-height: 320px; }
        table { font-size: 0.9rem; }
        th { white-space: nowrap; }
        .pill { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.75rem; margin-right: 0.25rem; background: var(--pico-muted-border-color); }
        .pill.critical { background: #c62828; color: white; }
        .pill.high     { background: #ef6c00; color: white; }
        .pill.medium   { background: #f9a825; color: black; }
        .pill.low      { background: #2e7d32; color: white; }
        .pill.info     { background: #0277bd; color: white; }
        .heatmap td { text-align: center; font-variant-numeric: tabular-nums; }
      </style>
    </head>
    <body>
      <main class="container">
        <hgroup>
          <h1>IaC Security Bake-Off</h1>
          <p>Per-tool comparison across the AWS and Azure manufactured-vulnerability stacks.</p>
        </hgroup>

        <section>
          <h2>Per-tool finding counts</h2>
          <div class="grid-2">
            <div><canvas id="severityChart"></canvas></div>
            <div><canvas id="totalsChart"></canvas></div>
          </div>
        </section>

        <section>
          <h2>Summary by tool &times; cloud</h2>
          <div id="summaryTable"></div>
        </section>

        <section>
          <h2>Tool overlap matrix</h2>
          <p><small>Diagonal = total findings reported by that tool. Off-diagonal = findings both tools agree on (same file:line:rule).</small></p>
          <div id="overlapTable"></div>
        </section>

        <section>
          <h2>Resource-level coverage</h2>
          <p><small>Each row is a unique <code>file:line</code>. The chips show which scanners flagged it.</small></p>
          <div id="resourceTable"></div>
        </section>

        <section>
          <h2>Unique findings (only one tool flagged it)</h2>
          <div id="uniqueTable"></div>
        </section>

        <footer>
          <small>Generated from <code>comparison.json</code>. Source data is the GitLab SAST artifacts produced by the per-tool GitHub Actions workflows.</small>
        </footer>
      </main>

      <script>
        const data = __DATA__;

        const severityColors = {
          Critical: "#c62828",
          High:     "#ef6c00",
          Medium:   "#f9a825",
          Low:      "#2e7d32",
          Info:     "#0277bd",
          Unknown:  "#9e9e9e"
        };
        const severities = ["Critical","High","Medium","Low","Info","Unknown"];

        // -----------------------------------------------------------------
        // Severity stacked bar
        // -----------------------------------------------------------------
        new Chart(document.getElementById("severityChart"), {
          type: "bar",
          data: {
            labels: data.tools,
            datasets: severities.map(sev => ({
              label: sev,
              backgroundColor: severityColors[sev],
              data: data.tools.map(t => {
                const perCloud = data.summary[t] || {};
                return Object.values(perCloud).reduce((acc, c) => acc + (c[sev] || 0), 0);
              })
            }))
          },
          options: {
            responsive: true,
            plugins: { title: { display: true, text: "Findings by severity (sum across clouds)" } },
            scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } }
          }
        });

        // -----------------------------------------------------------------
        // Totals bar
        // -----------------------------------------------------------------
        new Chart(document.getElementById("totalsChart"), {
          type: "bar",
          data: {
            labels: data.tools,
            datasets: [{
              label: "Total findings",
              backgroundColor: "#3949ab",
              data: data.tools.map(t => data.totals[t] || 0)
            }]
          },
          options: {
            responsive: true,
            plugins: { title: { display: true, text: "Total findings per tool" }, legend: { display: false } },
            scales: { y: { beginAtZero: true } }
          }
        });

        // -----------------------------------------------------------------
        // Summary table
        // -----------------------------------------------------------------
        function renderSummaryTable() {
          const clouds = data.clouds;
          const head = ["Tool", ...clouds.flatMap(c => severities.map(s => `${c}/${s}`)), "Total"];
          let html = "<table><thead><tr>" + head.map(h => `<th>${h}</th>`).join("") + "</tr></thead><tbody>";
          for (const tool of data.tools) {
            const perCloud = data.summary[tool] || {};
            const cells = clouds.flatMap(c => {
              const sevs = perCloud[c] || {};
              return severities.map(s => sevs[s] || 0);
            });
            html += `<tr><td><strong>${tool}</strong></td>` + cells.map(c => `<td>${c}</td>`).join("") + `<td><strong>${data.totals[tool] || 0}</strong></td></tr>`;
          }
          html += "</tbody></table>";
          document.getElementById("summaryTable").innerHTML = html;
        }
        renderSummaryTable();

        // -----------------------------------------------------------------
        // Overlap matrix
        // -----------------------------------------------------------------
        function renderOverlap() {
          let html = `<table class="heatmap"><thead><tr><th></th>` + data.tools.map(t => `<th>${t}</th>`).join("") + `</tr></thead><tbody>`;
          for (const a of data.tools) {
            html += `<tr><th>${a}</th>`;
            for (const b of data.tools) {
              const v = (data.overlap_matrix[a] || {})[b] || 0;
              const max = Math.max(...data.tools.map(t => (data.overlap_matrix[a] || {})[t] || 0));
              const intensity = max ? Math.round((v / max) * 70) + 15 : 0;
              const bg = a === b ? "#333" : `rgba(57, 73, 171, ${intensity / 100})`;
              html += `<td style="background:${bg};color:${a===b||intensity>50?"white":"inherit"}">${v}</td>`;
            }
            html += `</tr>`;
          }
          html += `</tbody></table>`;
          document.getElementById("overlapTable").innerHTML = html;
        }
        renderOverlap();

        // -----------------------------------------------------------------
        // Resource coverage table (one section per cloud)
        // -----------------------------------------------------------------
        function renderResources() {
          let html = "";
          for (const cloud of data.clouds) {
            const rows = (data.by_resource || {})[cloud] || [];
            html += `<details${cloud === data.clouds[0] ? " open" : ""}><summary><strong>${cloud.toUpperCase()}</strong> (${rows.length} unique file:line)</summary>`;
            html += `<table><thead><tr><th>File</th><th>Line</th><th>Found by</th><th>Missed by</th><th>Rules</th></tr></thead><tbody>`;
            for (const r of rows) {
              const found = r.found_by.map(t => `<span class="pill">${t}</span>`).join("");
              const missed = r.missed_by.map(t => `<span class="pill" style="opacity:0.4">${t}</span>`).join("");
              const rules = r.rule_ids.slice(0,3).join(", ") + (r.rule_ids.length>3 ? `, +${r.rule_ids.length-3}` : "");
              html += `<tr><td><code>${r.file}</code></td><td>${r.line}</td><td>${found}</td><td>${missed}</td><td><small>${rules}</small></td></tr>`;
            }
            html += `</tbody></table></details>`;
          }
          document.getElementById("resourceTable").innerHTML = html;
        }
        renderResources();

        // -----------------------------------------------------------------
        // Unique findings (per tool)
        // -----------------------------------------------------------------
        function renderUnique() {
          let html = "";
          for (const tool of data.tools) {
            const perCloud = (data.unique_findings || {})[tool] || {};
            const total = Object.values(perCloud).reduce((acc,a) => acc + a.length, 0);
            html += `<details><summary><strong>${tool}</strong>: ${total} unique findings</summary>`;
            for (const cloud of Object.keys(perCloud)) {
              html += `<h4>${cloud}</h4><table><thead><tr><th>File</th><th>Line</th><th>Severity</th><th>Rule</th><th>Name</th></tr></thead><tbody>`;
              for (const f of perCloud[cloud]) {
                html += `<tr><td><code>${f.file}</code></td><td>${f.line}</td><td><span class="pill ${f.severity.toLowerCase()}">${f.severity}</span></td><td><code>${f.rule_id}</code></td><td><small>${f.name||""}</small></td></tr>`;
              }
              html += `</tbody></table>`;
            }
            html += `</details>`;
          }
          document.getElementById("uniqueTable").innerHTML = html;
        }
        renderUnique();
      </script>
    </body>
    </html>
    """
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    data = json.loads(args.input.read_text())
    html = HTML_TEMPLATE.replace("__DATA__", json.dumps(data))
    args.output.write_text(html)
    print(f"Wrote dashboard to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
