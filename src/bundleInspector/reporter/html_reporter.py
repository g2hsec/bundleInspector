"""
HTML report generator.
"""

from __future__ import annotations

import json

from jinja2 import Environment

from bundleInspector.reporter.base import BaseReporter
from bundleInspector.reporter.explain import explain_finding, flow_steps, highlight_snippet
from bundleInspector.reporter.redaction import sanitize_report_copy
from bundleInspector.storage.models import Finding, Report, Severity

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BundleInspector Report - {{ report.id[:8] }}</title>
    <style>
        :root {
            color-scheme: light dark;
            --ui: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --mono: "SFMono-Regular", "SF Mono", "Consolas", "Liberation Mono", Menlo, monospace;
            /* neutral document surfaces */
            --page: #f3f4f6;
            --surface: #ffffff;
            --surface-2: #f8f9fb;
            --border: #e5e7eb;
            --border-strong: #d1d5db;
            --text: #1f2937;
            --text-muted: #586071;
            --text-faint: #8b94a1;
            --link: #2a5db0;
            /* code */
            --code-bg: #f8f9fb;
            --code-border: #e5e7eb;
            --hl-line: rgba(180,110,20,0.09);
            --mark-bg: #fce7cf;
            --mark-text: #7a3d00;
            /* semantic severity: [text, tint bg, tint border] -- used sparingly */
            --crit: #b42318; --crit-bg: #fef3f2; --crit-bd: #fdd6d1;
            --high: #b23a10; --high-bg: #fff4ec; --high-bd: #fbdcb9;
            --med:  #8a6410; --med-bg:  #fdf6e3; --med-bd:  #f3e0a6;
            --low:  #0a6c41; --low-bg:  #ecfdf3; --low-bd:  #b8ecc9;
            --info: #1a5ac9; --info-bg: #eef5ff; --info-bd: #c3daf9;
            --confirmed: #0a6c41;
            --download: #5b28d6; --download-bg: #f3f1ff; --download-bd: #dcd7fb;
            --chip-bg: #f2f4f7; --chip-text: #4a5361; --chip-bd: #e2e6ec;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --page: #0e1217; --surface: #151a21; --surface-2: #1a2028;
                --border: #28303a; --border-strong: #38424e;
                --text: #e5e9ef; --text-muted: #9aa4b1; --text-faint: #6c7684; --link: #7ea6e6;
                --code-bg: #0f141a; --code-border: #28303a;
                --hl-line: rgba(224,164,88,0.12); --mark-bg: #5b3a12; --mark-text: #ffe0b8;
                --crit: #f7a199; --crit-bg: #2a1512; --crit-bd: #582019;
                --high: #f0b58a; --high-bg: #271811; --high-bd: #4d2c15;
                --med:  #e6c66a; --med-bg:  #241f10; --med-bd:  #4a3d17;
                --low:  #6fd39b; --low-bg:  #0f2418; --low-bd:  #1f4a31;
                --info: #93c0f5; --info-bg: #101d2e; --info-bd: #213a5a;
                --confirmed: #0e7a49;
                --download: #b9a6ff; --download-bg: #1b1730; --download-bd: #342a5e;
                --chip-bg: #232a34; --chip-text: #aeb8c4; --chip-bd: #333c49;
            }
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--ui);
            background: var(--page);
            color: var(--text);
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
            -webkit-print-color-adjust: exact; print-color-adjust: exact;
        }
        .container { max-width: 1040px; margin: 0 auto; padding: 28px 24px 48px; }
        .mono { font-family: var(--mono); }
        .dim { color: var(--text-faint); }
        code { font-family: var(--mono); }

        /* ---- masthead ---- */
        .masthead {
            background: var(--surface); border: 1px solid var(--border);
            border-radius: 10px; padding: 22px 24px; margin-bottom: 20px;
        }
        .mh-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap; }
        .mh-brand { display: flex; gap: 14px; align-items: center; }
        .mh-logo {
            display: inline-flex; align-items: center; justify-content: center;
            width: 40px; height: 40px; border-radius: 9px;
            background: var(--text); color: var(--surface);
            font-weight: 700; font-size: 15px; letter-spacing: 0.02em; flex: 0 0 auto;
        }
        .masthead h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.02em; color: var(--text); }
        .mh-sub { font-size: 13px; color: var(--text-muted); margin-top: 2px; }
        .mh-id { text-align: right; }
        .mh-id-label { font-size: 10px; font-weight: 700; letter-spacing: 0.08em; color: var(--text-faint); }
        .mh-id-val { font-family: var(--mono); font-size: 14px; color: var(--text-muted); margin-top: 2px; }
        .meta-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px 24px; margin-top: 18px; padding-top: 18px; border-top: 1px solid var(--border);
        }
        .meta-grid dt {
            font-size: 10.5px; font-weight: 700; letter-spacing: 0.06em;
            text-transform: uppercase; color: var(--text-faint); margin-bottom: 3px;
        }
        .meta-grid dd { font-size: 13.5px; color: var(--text); word-break: break-word; }
        .meta-grid dd.mono { font-size: 12.5px; color: var(--text-muted); }

        /* ---- summary ---- */
        .metrics {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 12px; margin-bottom: 14px;
        }
        .metric { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
        .metric-num { font-size: 26px; font-weight: 700; letter-spacing: -0.02em; color: var(--text); line-height: 1.1; }
        .metric.accent .metric-num { color: var(--link); }
        .metric.muted .metric-num { color: var(--text-faint); }
        .metric-lbl { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
        .dist { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
        .dist-bar { display: flex; height: 10px; border-radius: 5px; overflow: hidden; background: var(--surface-2); }
        .dist-seg { height: 100%; }
        .dist-seg.critical { background: var(--crit); }
        .dist-seg.high { background: var(--high); }
        .dist-seg.medium { background: var(--med); }
        .dist-seg.low { background: var(--low); }
        .dist-seg.info { background: var(--info); }
        .dist-legend { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 11px; font-size: 12px; color: var(--text-muted); }
        .legend-item { display: inline-flex; align-items: center; gap: 6px; }
        .legend-item b { color: var(--text); font-weight: 650; }
        .legend-dot { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
        .legend-dot.critical { background: var(--crit); }
        .legend-dot.high { background: var(--high); }
        .legend-dot.medium { background: var(--med); }
        .legend-dot.low { background: var(--low); }
        .legend-dot.info { background: var(--info); }

        /* ---- sections ---- */
        .section { margin: 28px 0; }
        .sec-title {
            font-size: 15px; font-weight: 650; color: var(--text); letter-spacing: -0.01em;
            margin: 0 0 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border);
            display: flex; align-items: baseline; gap: 8px;
        }
        .sec-count {
            font-size: 12px; font-weight: 600; color: var(--text-muted);
            background: var(--surface-2); border: 1px solid var(--border);
            border-radius: 20px; padding: 1px 9px;
        }

        /* ---- badges / chips ---- */
        .badge {
            display: inline-flex; align-items: center; gap: 4px;
            font-size: 11px; font-weight: 600; line-height: 1.4; letter-spacing: 0.02em;
            padding: 2px 7px; border-radius: 5px; border: 1px solid transparent; white-space: nowrap;
        }
        .badge.critical { color: var(--crit); background: var(--crit-bg); border-color: var(--crit-bd); }
        .badge.high { color: var(--high); background: var(--high-bg); border-color: var(--high-bd); }
        .badge.medium { color: var(--med); background: var(--med-bg); border-color: var(--med-bd); }
        .badge.low { color: var(--low); background: var(--low-bg); border-color: var(--low-bd); }
        .badge.info { color: var(--info); background: var(--info-bg); border-color: var(--info-bd); }
        .badge.tier {
            color: var(--text-muted); background: var(--surface-2); border-color: var(--border);
            text-transform: uppercase; font-size: 10px; letter-spacing: 0.05em;
        }
        .badge.confirmed { color: #fff; background: var(--confirmed); border-color: transparent; font-weight: 700; }
        .badge.thirdparty { color: var(--chip-text); background: var(--chip-bg); border-color: var(--chip-bd); font-weight: 500; }
        .badge.fp { color: var(--chip-text); background: var(--chip-bg); border-color: var(--chip-bd); }
        .badge.download { color: var(--download); background: var(--download-bg); border-color: var(--download-bd); }
        .badge.download.possible { background: transparent; border-style: dashed; }

        /* ---- severity table ---- */
        .table-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
        th {
            text-align: left; font-size: 11px; font-weight: 700; letter-spacing: 0.04em;
            text-transform: uppercase; color: var(--text-faint);
            padding: 11px 16px; border-bottom: 1px solid var(--border);
        }
        td { padding: 11px 16px; border-bottom: 1px solid var(--border); color: var(--text); }
        tbody tr:last-child td { border-bottom: none; }
        .col-muted { color: var(--text-faint); }
        .table-note { font-size: 12px; color: var(--text-muted); padding: 11px 16px 12px; }
        .table-note strong { color: var(--text); }

        /* ---- findings ---- */
        .noise-banner {
            font-size: 13px; color: var(--text-muted);
            background: var(--surface-2); border: 1px solid var(--border);
            border-left: 3px solid var(--med); padding: 10px 14px; border-radius: 6px; margin: 12px 0;
        }
        .completeness-banner {
            font-size: 13px; color: var(--text); background: var(--med-bg);
            border: 1px solid var(--med-bd); border-left: 3px solid var(--med);
            padding: 11px 14px; border-radius: 6px; margin: 0 0 18px;
        }
        .completeness-banner strong { text-transform: uppercase; }
        .noise-banner strong { color: var(--text); }
        .muted-inline { color: var(--text-faint); }
        .filter-bar {
            display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
            justify-content: space-between; margin: 14px 0;
        }
        .segmented {
            display: inline-flex; background: var(--surface-2); border: 1px solid var(--border);
            border-radius: 8px; padding: 3px; gap: 2px;
        }
        .filter-btn {
            font: inherit; font-size: 13px; font-weight: 500; color: var(--text-muted);
            background: transparent; border: none; border-radius: 6px; padding: 6px 14px;
            cursor: pointer; transition: background .12s, color .12s;
        }
        .segmented .filter-btn:hover { color: var(--text); background: var(--surface); }
        .segmented .filter-btn.active {
            color: var(--text); background: var(--surface);
            box-shadow: 0 1px 2px rgba(16,24,40,.06); font-weight: 600;
        }
        .noise-toggle {
            border: 1px solid var(--border); border-radius: 8px; background: var(--surface);
            color: var(--text-muted); padding: 7px 14px;
        }
        .noise-toggle:hover { border-color: var(--border-strong); color: var(--text); }
        .noise-toggle.active { background: var(--chip-bg); border-color: var(--border-strong); color: var(--text); }

        .finding {
            background: var(--surface); border: 1px solid var(--border);
            border-left: 3px solid var(--border-strong); border-radius: 8px;
            padding: 16px 18px; margin-bottom: 12px;
        }
        .finding.critical { border-left-color: var(--crit); }
        .finding.high { border-left-color: var(--high); }
        .finding.medium { border-left-color: var(--med); }
        .finding.low { border-left-color: var(--low); }
        .finding.info { border-left-color: var(--info); }
        /* likely-FP / vendor findings: dimmed + dashed rule, demoted (never dropped) */
        .finding.noise { opacity: 0.6; border-left-style: dashed; }
        .finding.noise:hover { opacity: 1; }
        .finding-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
        .finding-title { font-size: 15px; font-weight: 650; color: var(--text); }
        .chips { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; justify-content: flex-end; }
        .finding-meta {
            display: flex; flex-wrap: wrap; gap: 6px; align-items: center;
            font-size: 12.5px; color: var(--text-muted); margin: 7px 0 12px;
        }
        .fm-cat { text-transform: capitalize; font-weight: 600; color: var(--text); }
        .fm-sep { color: var(--text-faint); }
        .fm-loc { display: inline-flex; align-items: center; gap: 4px; }
        .fm-loc .ic { color: var(--text-faint); flex: 0 0 auto; }
        .fm-src { color: var(--text-faint); }

        .fp-note {
            font-size: 12.5px; color: var(--text-muted); background: var(--surface-2);
            border: 1px solid var(--border); border-left: 3px solid var(--border-strong);
            padding: 7px 12px; border-radius: 6px; margin: 8px 0;
        }
        /* Why / Impact / Fix rationale */
        .rationale {
            display: grid; gap: 7px; margin: 10px 0; padding: 12px 14px;
            background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px;
        }
        .ra { display: flex; gap: 12px; font-size: 13.5px; line-height: 1.5; }
        .ra-text { color: var(--text); }
        .lbl {
            display: inline-block; font-size: 10.5px; font-weight: 700; letter-spacing: 0.06em;
            text-transform: uppercase; color: var(--text-faint);
        }
        .ra .lbl { flex: 0 0 auto; min-width: 52px; padding-top: 2px; }
        .lbl.impact { color: var(--high); }
        .lbl.fix { color: var(--low); }
        .lbl.danger { color: var(--crit); }
        .lbl.dl { color: var(--download); }

        /* Source -> tainted value -> Sink strip */
        .flow {
            display: flex; flex-wrap: wrap; align-items: center; gap: 6px;
            background: var(--surface-2); border: 1px solid var(--border);
            padding: 8px 10px; border-radius: 6px; margin: 10px 0; font-size: 12.5px;
        }
        .flow-step {
            display: inline-flex; align-items: center; gap: 6px; padding: 3px 8px;
            border-radius: 5px; border: 1px solid var(--border-strong); background: var(--surface);
        }
        .flow-step.source { border-color: var(--low-bd); }
        .flow-step.value  { border-color: var(--med-bd); }
        .flow-step.sink   { border-color: var(--crit-bd); }
        .flow-kind { font-size: 10px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }
        .flow-step.source .flow-kind { color: var(--low); }
        .flow-step.value  .flow-kind { color: var(--med); }
        .flow-step.sink   .flow-kind { color: var(--crit); }
        .flow-step code { font-family: var(--mono); font-size: 12px; color: var(--text); }
        .flow-line { color: var(--text-faint); font-size: 11px; }
        .flow-arrow { color: var(--text-faint); font-weight: 600; }

        /* the specific value that reaches the sink -- "where is it vulnerable" */
        .danger-value {
            display: flex; flex-wrap: wrap; align-items: center; gap: 8px;
            background: var(--crit-bg); border: 1px solid var(--crit-bd); border-left: 3px solid var(--crit);
            padding: 8px 12px; border-radius: 6px; margin: 10px 0; font-size: 13px;
        }
        .danger-value code { font-family: var(--mono); color: var(--crit); font-weight: 600; }

        /* file-download surface descriptor */
        .download-note {
            background: var(--download-bg); border: 1px solid var(--download-bd);
            border-left: 3px solid var(--download); padding: 8px 12px; border-radius: 6px;
            margin: 10px 0; font-size: 13px;
        }
        .download-note.possible { border-left-style: dashed; }
        .download-note code {
            font-family: var(--mono); color: var(--download); background: var(--surface);
            padding: 1px 5px; border-radius: 4px; border: 1px solid var(--download-bd);
        }
        .dl-note { margin-top: 5px; color: var(--text-muted); }

        .finding-desc { font-size: 13.5px; color: var(--text-muted); margin: 8px 0; }

        .evidence {
            font-size: 13px; margin: 10px 0; padding: 8px 12px;
            background: var(--code-bg); border: 1px solid var(--code-border);
            border-radius: 6px; overflow-x: auto;
        }
        .ev-label {
            font-size: 10.5px; font-weight: 700; letter-spacing: 0.06em;
            text-transform: uppercase; color: var(--text-faint); margin-right: 8px;
        }
        .evidence code { color: var(--text); }

        /* line-numbered, highlighted code snippet */
        .code-cap {
            font-size: 10.5px; font-weight: 600; letter-spacing: 0.05em;
            text-transform: uppercase; color: var(--text-faint); margin: 12px 0 5px;
        }
        .code {
            background: var(--code-bg); border: 1px solid var(--code-border); border-radius: 6px;
            padding: 10px 0; overflow-x: auto; font-family: var(--mono); font-size: 12.5px; line-height: 1.6;
        }
        .code .cl { display: block; white-space: pre; padding: 0 12px; }
        .code .cl.hl { background: var(--hl-line); border-left: 2px solid var(--high); }
        .code .ln {
            display: inline-block; width: 3em; text-align: right;
            margin-right: 14px; color: var(--text-faint); user-select: none;
        }
        .code .src { color: var(--text); }
        .code mark { background: var(--mark-bg); color: var(--mark-text); border-radius: 3px; padding: 0 2px; font-weight: 600; }

        .tags { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 12px; }
        .tag {
            font-family: var(--mono); font-size: 11px; color: var(--text-muted);
            background: var(--surface-2); border: 1px solid var(--border);
            padding: 2px 7px; border-radius: 4px;
        }

        /* ---- errors / footer ---- */
        .errors { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        .error-row {
            padding: 10px 14px; font-family: var(--mono); font-size: 12.5px;
            color: var(--text-muted); border-bottom: 1px solid var(--border);
        }
        .error-row:last-child { border-bottom: none; }
        .report-footer {
            margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border);
            font-size: 12px; color: var(--text-faint); text-align: center;
        }

        @media (max-width: 640px) {
            .container { padding: 20px 16px 40px; }
            .finding-header { flex-direction: column; align-items: flex-start; }
            .chips { justify-content: flex-start; }
            .mh-id { text-align: left; }
        }
        @media print {
            body { background: #fff; }
            .filter-bar { display: none; }
            .masthead, .metric, .dist, .table-card, .finding { break-inside: avoid; }
            .finding.noise { opacity: 1 !important; display: block !important; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="masthead">
            <div class="mh-top">
                <div class="mh-brand">
                    <span class="mh-logo" aria-hidden="true">BI</span>
                    <div>
                        <h1>BundleInspector</h1>
                        <div class="mh-sub">JavaScript Bundle Security Report</div>
                    </div>
                </div>
                <div class="mh-id">
                    <div class="mh-id-label">REPORT</div>
                    <div class="mh-id-val">{{ report.id[:8] }}</div>
                </div>
            </div>
            <dl class="meta-grid">
                <div><dt>Target</dt><dd>{{ report.seed_urls | join(', ') or '&mdash;' }}</dd></div>
                <div><dt>Generated</dt><dd>{{ report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</dd></div>
                <div><dt>Duration</dt><dd>{{ "%.2f"|format(report.duration_seconds) }} s</dd></div>
                <div><dt>Report ID</dt><dd class="mono">{{ report.id }}</dd></div>
            </dl>
        </header>

        {% if not report.completeness.is_complete %}
        <div class="completeness-banner" role="status">
            <strong>{{ report.completeness.status.value }} analysis.</strong>
            Some inputs or stages were not fully analyzed; findings are not a complete inventory.
            {% if report.completeness.retryable %}A retry may recover missing coverage.{% endif %}
        </div>
        {% endif %}

        <section class="summary">
            <div class="metrics">
                <div class="metric">
                    <div class="metric-num">{{ report.summary.total_js_files }}</div>
                    <div class="metric-lbl">JS files analyzed</div>
                </div>
                <div class="metric">
                    <div class="metric-num">{{ report.summary.total_findings }}</div>
                    <div class="metric-lbl">Total findings</div>
                </div>
                <div class="metric accent">
                    <div class="metric-num">{{ first_party_count }}</div>
                    <div class="metric-lbl">First-party to review</div>
                </div>
                <div class="metric muted">
                    <div class="metric-num">{{ noise_count }}</div>
                    <div class="metric-lbl">Demoted as noise</div>
                </div>
            </div>
            {% if grand_total > 0 %}
            <div class="dist">
                <div class="dist-bar">
                    {% for r in sev_rows %}<span class="dist-seg {{ r.sev }}" style="width:{{ '%.4f'|format(r.total * 100.0 / grand_total) }}%" title="{{ r.sev | upper }}: {{ r.total }}"></span>{% endfor %}
                </div>
                <div class="dist-legend">
                    {% for r in sev_rows %}<span class="legend-item"><span class="legend-dot {{ r.sev }}"></span>{{ r.sev | upper }} <b>{{ r.total }}</b></span>{% endfor %}
                </div>
            </div>
            {% endif %}
        </section>

        <section class="section">
            <h2 class="sec-title">Severity distribution</h2>
            <div class="table-card">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th title="First-party findings shown by default">First-party</th>
                            <th title="Vendor / likely-FP findings hidden by default">Demoted (noise)</th>
                            <th>Total</th>
                        </tr>
                    </thead>
                    <tbody>
                    {% for r in sev_rows %}
                        <tr>
                            <td><span class="badge {{ r.sev }}">{{ r.sev | upper }}</span></td>
                            <td><strong>{{ r.fp }}</strong></td>
                            <td class="col-muted">{{ r.noise }}</td>
                            <td>{{ r.total }}</td>
                        </tr>
                    {% endfor %}
                    </tbody>
                </table>
                <p class="table-note">
                    <strong>First-party</strong> = findings shown by default (what to review).
                    <strong>Demoted</strong> = vendor / likely-FP hidden by default &mdash; e.g. a CRITICAL here is a library string, not app code.
                </p>
            </div>
        </section>

        <section class="section">
            <h2 class="sec-title">Findings <span class="sec-count">{{ findings_view | length }}</span></h2>
            {% if noise_count > 0 %}
            <div class="noise-banner">
                Showing <strong>{{ first_party_count }}</strong> first-party finding{{ 's' if first_party_count != 1 }} to review &mdash;
                <strong>{{ noise_count }}</strong> vendor / likely-FP finding{{ 's' if noise_count != 1 }} hidden (kept in the report; use the toggle to show).
                <span class="muted-inline">These are not all vulnerabilities &mdash; endpoints/flags are attack surface. Sorted by severity; confirmed dataflows &amp; injections rank first.</span>
            </div>
            {% endif %}
            <div class="filter-bar">
                <div class="segmented">
                    <button class="filter-btn active" onclick="setSeverity(event, 'all')">All</button>
                    <button class="filter-btn" onclick="setSeverity(event, 'critical')">Critical</button>
                    <button class="filter-btn" onclick="setSeverity(event, 'high')">High</button>
                    <button class="filter-btn" onclick="setSeverity(event, 'medium')">Medium</button>
                    <button class="filter-btn" onclick="setSeverity(event, 'low')">Low</button>
                </div>
                <button class="filter-btn noise-toggle" onclick="toggleNoise(this)"
                    title="Show/hide third-party library findings and likely false positives">Show vendor / likely-FP noise</button>
            </div>

            {% for v in findings_view %}
            {% set finding = v.f %}
            <article class="finding {{ finding.severity.value }}{% if v.noise %} noise{% endif %}" data-severity="{{ finding.severity.value }}" data-noise="{{ '1' if v.noise else '0' }}">
                <div class="finding-header">
                    <span class="finding-title">{{ finding.title }}</span>
                    <div class="chips">
                        {% if v.confirmed %}<span class="badge confirmed">&#10003; CONFIRMED</span>{% endif %}
                        {% if v.download %}<span class="badge download{% if v.download.certainty != 'confirmed' %} possible{% endif %}" title="file-download surface">{% if v.download.certainty == 'confirmed' %}DOWNLOAD: {{ v.download.primary_risk | replace('_','-') }}{% else %}DOWNLOAD? verify{% endif %}</span>{% endif %}
                        {% if v.likely_fp %}<span class="badge fp" title="{{ v.fp_reason }}">LIKELY FP</span>{% endif %}
                        {% if v.third_party %}<span class="badge thirdparty" title="third-party library file">3p: {{ v.third_party }}</span>{% endif %}
                        <span class="badge {{ finding.severity.value }}">{{ finding.severity.value | upper }}</span>
                        {% if finding.risk_tier %}<span class="badge tier">{{ finding.risk_tier.value }}</span>{% endif %}
                    </div>
                </div>

                <div class="finding-meta">
                    <span class="fm-cat">{{ finding.category.value }}</span>
                    <span class="fm-sep">&middot;</span>
                    <span>{{ finding.confidence.value }} confidence</span>
                    <span class="fm-sep">&middot;</span>
                    <span class="fm-loc"><svg class="ic" width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M13 6.5c0 3.5-5 7.5-5 7.5s-5-4-5-7.5a5 5 0 0 1 10 0Z"/><circle cx="8" cy="6.5" r="1.6"/></svg><span class="mono">{{ finding.evidence.file_url }}:{{ finding.evidence.line }}</span>{% if finding.evidence.original_file_url or finding.evidence.original_line %}<span class="fm-src">&nbsp;source: <span class="mono">{{ finding.evidence.original_file_url or finding.evidence.file_url }}:{{ finding.evidence.original_line or finding.evidence.line }}</span></span>{% endif %}</span>
                </div>

                {% if v.likely_fp %}<div class="fp-note">Likely false positive &mdash; {{ v.fp_reason }}. Demoted, not dropped.</div>{% endif %}

                <div class="rationale">
                    <div class="ra"><span class="lbl">Why</span><span class="ra-text">{{ v.explain.why }}</span></div>
                    <div class="ra"><span class="lbl impact">Impact</span><span class="ra-text">{{ v.explain.impact }}</span></div>
                    <div class="ra"><span class="lbl fix">Fix</span><span class="ra-text">{{ v.explain.fix }}</span></div>
                </div>

                {% if v.download %}
                <div class="download-note{% if v.download.certainty != 'confirmed' %} possible{% endif %}">
                    <span class="lbl dl">{% if v.download.certainty == 'confirmed' %}Download surface{% else %}Possible download{% endif %}</span>
                    <strong>{{ v.download.primary_risk | replace('_','-') }}</strong>
                    <span class="dim">({{ v.download.confidence }} confidence{% if v.download.signals.mechanism %}, file response: {{ v.download.signals.mechanism }}{% endif %})</span>
                    {% if v.download.params %}<span class="dim">&middot; param(s):</span>
                        {% for role, names in v.download.params.items() %}{% for n in names %}<code>{{ n }}</code> {% endfor %}{% endfor %}
                    {% endif %}
                    <div class="dl-note">{{ v.download.note }}</div>
                </div>
                {% endif %}

                {% if v.danger_value and not v.flow %}
                <div class="danger-value"><span class="lbl danger">DANGEROUS VALUE</span><code>{{ v.danger_value }}</code><span class="dim">&larr; the value that reaches the sink; XSS if it is attacker-influenced</span></div>
                {% endif %}

                {% if v.flow %}
                <div class="flow">
                    {% for step in v.flow %}<span class="flow-step {{ step.kind }}"><span class="flow-kind">{{ step.kind | upper }}</span><code>{{ step.label }}</code>{% if step.line %}<span class="flow-line">L{{ step.line }}</span>{% endif %}</span>{% if not loop.last %}<span class="flow-arrow">&rarr;</span>{% endif %}{% endfor %}
                </div>
                {% else %}
                <p class="finding-desc">{{ finding.description }}</p>
                {% endif %}

                {% if finding.masked_value or finding.extracted_value %}
                <div class="evidence"><span class="ev-label">Value</span><code>{{ finding.masked_value or finding.extracted_value[:100] }}{% if not finding.masked_value and finding.extracted_value|length > 100 %}...{% endif %}</code></div>
                {% endif %}

                {% if v.snippet_html %}
                <div class="code-cap">Code <span class="dim">(highlighted = the matched value that triggered this finding)</span></div>
                <div class="code">{{ v.snippet_html | safe }}</div>
                {% endif %}

                {% if finding.metadata.get('original_snippet') %}
                <div class="code-cap">ORIGINAL SOURCE <span class="dim">(source-mapped)</span></div>
                <div class="code"><span class="cl"><span class="src">{{ finding.metadata.get('original_snippet') }}</span></span></div>
                {% endif %}

                {% if finding.tags %}
                <div class="tags">
                    {% for tag in finding.tags %}<span class="tag">{{ tag }}</span>{% endfor %}
                </div>
                {% endif %}
            </article>
            {% endfor %}
        </section>

        {% if report.clusters %}
        <section class="section">
            <h2 class="sec-title">Clusters <span class="sec-count">{{ report.clusters | length }}</span></h2>
            {% for cluster in report.clusters %}
            <article class="finding info">
                <div class="finding-header">
                    <span class="finding-title">{{ cluster.name }}</span>
                    <div class="chips"><span class="badge info">{{ cluster.size }} findings</span></div>
                </div>
                <p class="finding-desc">{{ cluster.description }}</p>
            </article>
            {% endfor %}
        </section>
        {% endif %}

        {% if report.errors %}
        <section class="section">
            <h2 class="sec-title">Errors <span class="sec-count">{{ report.errors | length }}</span></h2>
            <div class="errors">
                {% for error in report.errors %}<div class="error-row">{{ error }}</div>{% endfor %}
            </div>
        </section>
        {% endif %}

        {% if report.warnings or report.completeness.issues %}
        <section class="section">
            <h2 class="sec-title">Warnings <span class="sec-count">{{ report.warnings | length + report.completeness.issues | length }}</span></h2>
            <div class="errors">
                {% for warning in report.warnings %}<div class="error-row">{{ warning }}</div>{% endfor %}
                {% for issue in report.completeness.issues %}<div class="error-row">[{{ issue.stage }}:{{ issue.code }}] {{ issue.message }}</div>{% endfor %}
            </div>
        </section>
        {% endif %}

        <footer class="report-footer">
            Generated by BundleInspector &middot; static + dynamic JavaScript bundle analysis &middot; Report {{ report.id[:8] }}
        </footer>
    </div>

    <script>
        // Severity and noise are two independent filters; a finding shows only if it passes both.
        // Noise (vendor / likely-FP) starts HIDDEN so the default view is the first-party findings.
        var curSeverity = 'all', hideNoise = true;
        function applyFilters() {
            document.querySelectorAll('.finding[data-severity]').forEach(function (f) {
                var okSev = (curSeverity === 'all' || f.dataset.severity === curSeverity);
                var okNoise = (!hideNoise || f.dataset.noise !== '1');
                f.style.display = (okSev && okNoise) ? 'block' : 'none';
            });
        }
        function setSeverity(e, severity) {
            curSeverity = severity;
            document.querySelectorAll('.filter-btn').forEach(function (b) {
                if (!b.classList.contains('noise-toggle')) b.classList.remove('active');
            });
            e.target.classList.add('active');
            applyFilters();
        }
        function toggleNoise(btn) {
            hideNoise = !hideNoise;
            btn.classList.toggle('active', !hideNoise);
            btn.textContent = hideNoise
                ? 'Show vendor / likely-FP noise'
                : 'Hide vendor / likely-FP noise';
            applyFilters();
        }
        // Apply the default (noise hidden) once the DOM is parsed. The script tag sits at the end
        // of <body>, so all .finding elements already exist.
        applyFilters();
    </script>
    <script id="bundleInspector-report-data" type="application/json">{{ report_json | safe }}</script>
</body>
</html>
"""


class HTMLReporter(BaseReporter):
    """Generate HTML reports."""

    name = "html"
    extension = ".html"

    def __init__(self, mask_secrets: bool = True, secret_visible_chars: int = 4):
        self.mask_secrets = mask_secrets
        self.secret_visible_chars = secret_visible_chars

    def generate(self, report: Report) -> str:
        """Generate HTML report."""
        # Render from a copy in both modes so compute_summary and presentation-only sorting never
        # change a shared or persisted report object.
        if self.mask_secrets:
            report = sanitize_report_copy(
                report,
                visible_chars=self.secret_visible_chars,
                honor_existing_mask=False,
            )
        else:
            report = report.model_copy(deep=True)
        report.compute_summary()
        # Redact secrets BEFORE rendering the template (objects) and dumping the embedded
        # JSON -- HTML previously never masked, leaking secrets in clear text.

        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        def _noise(f: Finding) -> bool:
            md = f.metadata or {}
            if md.get("confirmed"):
                return False  # a proven source->sink flow is never noise, even in a vendor file
            return bool(md.get("likely_fp") or md.get("third_party_file"))

        # Real app findings first; likely-noise (vendor files / likely-FP) sinks to the bottom,
        # then by severity + risk.
        findings_sorted = sorted(
            report.findings,
            key=lambda f: (1 if _noise(f) else 0, severity_order.get(f.severity, 5), -f.risk_score)
        )

        # Enrich each finding with a plain-language why/impact/fix, a structured source->sink flow
        # (taint only), a line-numbered/highlighted snippet, and the noise/dangerous-field cues --
        # so the report reads as "why is this a risk + how does the code tie to it + is it noise",
        # not a bare pattern dump.
        findings_view = [
            {
                "f": f,
                "explain": explain_finding(f),
                "flow": flow_steps(f),
                "snippet_html": highlight_snippet(f),
                "confirmed": bool((f.metadata or {}).get("confirmed")),
                "noise": _noise(f),
                "likely_fp": bool((f.metadata or {}).get("likely_fp")),
                "fp_reason": (f.metadata or {}).get("fp_reason") or "",
                "third_party": (f.metadata or {}).get("third_party_file") or "",
                # the specific server/user value that reaches the sink -- WHERE it is vulnerable
                "danger_value": (f.metadata or {}).get("sink_source") or "",
                # file-download surface descriptor (risk / params / note), if any
                "download": (f.metadata or {}).get("download_surface") or None,
            }
            for f in findings_sorted
        ]

        # Exclude asset byte payloads INSIDE model_dump so json-mode serialization never utf-8-decodes
        # non-UTF8 asset bytes and crashes (DQ-O14); HTML never embeds raw content anyway.
        report_data = report.model_dump(
            mode="json",
            exclude_none=True,
            exclude={"assets": {"__all__": {"content", "sourcemap_content"}}},
        )
        # Escape every "<" as its JSON unicode escape so NO HTML tag (incl. `</script`
        # followed by space/slash, `<!--`, `<script`) can break out of the embedded
        # <script type="application/json"> block. `<` is valid JSON and renders back to
        # "<" when parsed. re.sub(r"</script>") alone missed the space/slash-terminated forms.
        report_json = json.dumps(report_data, ensure_ascii=False).replace("<", "\\u003c")

        env = Environment(autoescape=True)
        template = env.from_string(HTML_TEMPLATE)
        noise_count = sum(1 for v in findings_view if v["noise"])
        # Severity split so the summary is CONSISTENT with the (noise-hidden) findings list: the
        # aggregate counted demoted noise (e.g. a vendor CRITICAL) that never appears in the default
        # view. Show first-party vs demoted vs total per severity.
        _sev_names = ["critical", "high", "medium", "low", "info"]
        fp_sev: dict = {}
        noise_sev: dict = {}
        for f in report.findings:
            s = getattr(getattr(f, "severity", None), "value", "info")
            (noise_sev if _noise(f) else fp_sev)[s] = (noise_sev if _noise(f) else fp_sev).get(s, 0) + 1
        sev_rows = [
            {"sev": s, "fp": fp_sev.get(s, 0), "noise": noise_sev.get(s, 0),
             "total": fp_sev.get(s, 0) + noise_sev.get(s, 0)}
            for s in _sev_names if (fp_sev.get(s, 0) + noise_sev.get(s, 0)) > 0
        ]
        return template.render(
            report=report,
            findings_sorted=findings_sorted,
            findings_view=findings_view,
            noise_count=noise_count,
            # NOT "real vulnerabilities" -- these are first-party findings after vendor/likely-FP
            # noise is removed; they still include attack surface (endpoints) and need triage.
            first_party_count=len(findings_view) - noise_count,
            sev_rows=sev_rows,
            # grand total across the severity split -- drives the distribution bar widths.
            grand_total=sum(r["total"] for r in sev_rows),
            report_json=report_json,
        )
