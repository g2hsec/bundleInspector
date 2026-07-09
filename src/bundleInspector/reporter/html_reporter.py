"""
HTML report generator.
"""

from __future__ import annotations

import json
import re

from jinja2 import Environment

from bundleInspector.reporter.base import BaseReporter, mask_secret_findings
from bundleInspector.reporter.explain import explain_finding, flow_steps, highlight_snippet
from bundleInspector.storage.models import Report, RiskTier, Severity


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BundleInspector Report - {{ report.id[:8] }}</title>
    <style>
        :root {
            --bg: #1a1a2e;
            --surface: #16213e;
            --primary: #0f3460;
            --accent: #e94560;
            --text: #eaeaea;
            --muted: #888;
            --critical: #ff4444;
            --high: #ff8800;
            --medium: #ffcc00;
            --low: #44ff44;
            --info: #4488ff;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            background: var(--surface);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        h1 { color: var(--accent); margin-bottom: 10px; }
        .meta { color: var(--muted); font-size: 0.9em; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: var(--surface);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .stat-value { font-size: 2.5em; font-weight: bold; color: var(--accent); }
        .stat-label { color: var(--muted); }
        .section {
            background: var(--surface);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .section h2 {
            color: var(--accent);
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--primary);
        }
        .finding {
            background: var(--primary);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }
        .finding.critical { border-color: var(--critical); }
        .finding.high { border-color: var(--high); }
        .finding.medium { border-color: var(--medium); }
        .finding.low { border-color: var(--low); }
        .finding.info { border-color: var(--info); }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .finding-title { font-weight: bold; font-size: 1.1em; }
        .badge {
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .badge.critical { background: var(--critical); }
        .badge.high { background: var(--high); color: #000; }
        .badge.medium { background: var(--medium); color: #000; }
        .badge.low { background: var(--low); color: #000; }
        .badge.info { background: var(--info); }
        .badge.tier { background: var(--accent); margin-left: 5px; }
        .badge.confirmed { background: #2ecc71; color: #062; margin-right: 5px; }
        .badge.thirdparty { background: #555; color: #ddd; margin-right: 5px; }
        .badge.fp { background: #7a5; color: #041; margin-right: 5px; }
        /* likely-false-positive / vendor findings: dimmed + dashed, demoted (never dropped) */
        .finding.noise { opacity: 0.55; border-style: dashed; }
        .finding.noise:hover { opacity: 1; }
        .fp-note {
            font-size: 0.82em; color: #cdb; background: rgba(120,150,80,0.12);
            border-left: 3px solid #7a5; padding: 5px 10px; border-radius: 4px; margin: 4px 0 8px;
        }
        .noise-toggle { margin-left: auto; }
        .noise-toggle.active { background: #7a5; color: #041; }
        .noise-banner {
            background: rgba(120,150,80,0.14); border-left: 3px solid #7a5;
            padding: 8px 12px; border-radius: 5px; margin-bottom: 12px; font-size: 0.92em;
        }
        /* the specific value that reaches the sink -- "where is it vulnerable" */
        .danger-value {
            background: rgba(255,68,68,0.10); border-left: 3px solid var(--critical);
            padding: 6px 10px; border-radius: 4px; margin: 4px 0 10px; font-size: 0.9em;
        }
        .danger-value code { color: #ffb3b3; font-family: 'Consolas', monospace; }
        .lbl.danger { background: var(--critical); color: #fff; }
        /* Why / Impact / Fix -- the "why is this a risk" panel */
        .why {
            background: rgba(233,69,96,0.12);
            border-left: 3px solid var(--accent);
            padding: 8px 12px;
            border-radius: 4px;
            margin: 4px 0 10px;
        }
        .lbl {
            display: inline-block;
            font-size: 0.68em;
            font-weight: bold;
            letter-spacing: 0.5px;
            padding: 1px 6px;
            border-radius: 3px;
            margin-right: 8px;
            vertical-align: middle;
            background: var(--accent);
            color: #fff;
        }
        .lbl.impact { background: var(--high); color: #000; }
        .lbl.fix { background: var(--low); color: #000; }
        .impact-fix { font-size: 0.9em; margin-bottom: 10px; }
        .impact-fix > div { margin: 3px 0; }
        /* Source -> tainted value -> Sink strip */
        .flow {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 6px;
            background: var(--bg);
            padding: 8px 10px;
            border-radius: 6px;
            margin-bottom: 10px;
            font-size: 0.85em;
        }
        .flow-step { padding: 3px 8px; border-radius: 4px; border: 1px solid; }
        .flow-step.source { border-color: var(--low); color: #b9ffb9; }
        .flow-step.value  { border-color: var(--medium); color: #ffe98a; }
        .flow-step.sink   { border-color: var(--critical); color: #ffb3b3; }
        .flow-kind {
            font-size: 0.72em; font-weight: bold; letter-spacing: 0.5px;
            margin-right: 6px; opacity: 0.85;
        }
        .flow-step code { font-family: 'Consolas', monospace; }
        .flow-line { color: var(--muted); margin-left: 6px; font-size: 0.85em; }
        .flow-arrow { color: var(--accent); font-weight: bold; }
        /* Line-numbered, highlighted code snippet */
        .code-cap { font-size: 0.72em; color: var(--muted); letter-spacing: 0.5px; margin: 6px 0 3px; }
        .code {
            background: var(--bg);
            border-radius: 5px;
            padding: 8px 0;
            overflow-x: auto;
            font-family: 'Consolas', monospace;
            font-size: 0.86em;
            line-height: 1.5;
        }
        .code .cl { display: block; white-space: pre; padding: 0 10px; }
        .code .cl.hl { background: rgba(255,204,0,0.10); border-left: 2px solid var(--high); }
        .code .ln {
            display: inline-block; width: 3.2em; text-align: right;
            margin-right: 12px; color: var(--muted); user-select: none;
        }
        .code mark { background: rgba(255,68,68,0.35); color: #fff; border-radius: 2px; padding: 0 1px; }
        .evidence {
            background: var(--bg);
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }
        .location { color: var(--muted); font-size: 0.85em; margin-top: 10px; }
        pre {
            background: var(--bg);
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        code { font-family: 'Consolas', monospace; }
        .tags { margin-top: 10px; }
        .tag {
            display: inline-block;
            background: var(--bg);
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            margin-right: 5px;
            color: var(--muted);
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid var(--primary);
        }
        th { color: var(--accent); }
        .filter-bar {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .filter-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            background: var(--primary);
            color: var(--text);
        }
        .filter-btn:hover { background: var(--accent); }
        .filter-btn.active { background: var(--accent); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>BundleInspector Security Report</h1>
            <div class="meta">
                <div>Report ID: {{ report.id }}</div>
                <div>Generated: {{ report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</div>
                <div>Duration: {{ "%.2f"|format(report.duration_seconds) }}s</div>
                <div>Targets: {{ report.seed_urls | join(', ') }}</div>
            </div>
        </header>

        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">{{ report.summary.total_js_files }}</div>
                <div class="stat-label">JS Files Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ report.summary.total_findings }}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ first_party_count }}</div>
                <div class="stat-label">First-party (to review)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:var(--muted)">{{ noise_count }}</div>
                <div class="stat-label">Demoted as noise</div>
            </div>
        </div>

        <div class="section">
            <h2>Severity Distribution</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th title="First-party findings shown by default">First-party</th>
                    <th title="Vendor / likely-FP findings hidden by default">Demoted (noise)</th>
                    <th>Total</th>
                </tr>
                {% for r in sev_rows %}
                <tr>
                    <td><span class="badge {{ r.sev }}">{{ r.sev | upper }}</span></td>
                    <td><strong>{{ r.fp }}</strong></td>
                    <td style="color:var(--muted)">{{ r.noise }}</td>
                    <td>{{ r.total }}</td>
                </tr>
                {% endfor %}
            </table>
            <p style="color:var(--muted);font-size:0.85em;margin-top:8px;">
                <strong>First-party</strong> = findings shown by default (what to review).
                <strong>Demoted</strong> = vendor / likely-FP hidden by default — e.g. a CRITICAL here is a library string, not app code.
            </p>
        </div>

        <div class="section">
            <h2>Findings</h2>
            {% if noise_count > 0 %}
            <div class="noise-banner">
                Showing <strong>{{ first_party_count }}</strong> first-party finding{{ 's' if first_party_count != 1 }} to review &mdash;
                <strong>{{ noise_count }}</strong> vendor / likely-FP finding{{ 's' if noise_count != 1 }} hidden (kept in the report; use the toggle to show).
                <span style="opacity:.75">These are not all vulnerabilities &mdash; endpoints/flags are attack surface. Sorted by severity; confirmed dataflows &amp; injections rank first.</span>
            </div>
            {% endif %}
            <div class="filter-bar">
                <button class="filter-btn active" onclick="setSeverity(event, 'all')">All</button>
                <button class="filter-btn" onclick="setSeverity(event, 'critical')">Critical</button>
                <button class="filter-btn" onclick="setSeverity(event, 'high')">High</button>
                <button class="filter-btn" onclick="setSeverity(event, 'medium')">Medium</button>
                <button class="filter-btn" onclick="setSeverity(event, 'low')">Low</button>
                <button class="filter-btn noise-toggle" onclick="toggleNoise(this)"
                    title="Show/hide third-party library findings and likely false positives">&#128065; Show vendor / likely-FP noise</button>
            </div>

            {% for v in findings_view %}
            {% set finding = v.f %}
            <div class="finding {{ finding.severity.value }}{% if v.noise %} noise{% endif %}" data-severity="{{ finding.severity.value }}" data-noise="{{ '1' if v.noise else '0' }}">
                <div class="finding-header">
                    <span class="finding-title">{{ finding.title }}</span>
                    <div>
                        {% if v.confirmed %}<span class="badge confirmed">CONFIRMED</span>{% endif %}
                        {% if v.likely_fp %}<span class="badge fp" title="{{ v.fp_reason }}">LIKELY FP</span>{% endif %}
                        {% if v.third_party %}<span class="badge thirdparty" title="third-party library file">3p:{{ v.third_party }}</span>{% endif %}
                        <span class="badge {{ finding.severity.value }}">{{ finding.severity.value | upper }}</span>
                        {% if finding.risk_tier %}<span class="badge tier">{{ finding.risk_tier.value }}</span>{% endif %}
                    </div>
                </div>

                {% if v.likely_fp %}<div class="fp-note">Likely false positive &mdash; {{ v.fp_reason }}. Demoted, not dropped.</div>{% endif %}

                <div class="why"><span class="lbl">WHY</span>{{ v.explain.why }}</div>

                {% if v.danger_value and not v.flow %}
                <div class="danger-value"><span class="lbl danger">DANGEROUS VALUE</span><code>{{ v.danger_value }}</code> &nbsp;<span style="opacity:.7">&larr; this is the value that reaches the sink; XSS if it is attacker-influenced</span></div>
                {% endif %}

                {% if v.flow %}
                <div class="flow">
                    {% for step in v.flow %}<span class="flow-step {{ step.kind }}"><span class="flow-kind">{{ step.kind | upper }}</span><code>{{ step.label }}</code>{% if step.line %}<span class="flow-line">L{{ step.line }}</span>{% endif %}</span>{% if not loop.last %}<span class="flow-arrow">&rarr;</span>{% endif %}{% endfor %}
                </div>
                {% else %}
                <p style="color:var(--muted);font-size:0.9em;margin-bottom:8px;">{{ finding.description }}</p>
                {% endif %}

                <div class="impact-fix">
                    <div><span class="lbl impact">IMPACT</span>{{ v.explain.impact }}</div>
                    <div><span class="lbl fix">FIX</span>{{ v.explain.fix }}</div>
                </div>

                {% if finding.masked_value or finding.extracted_value %}
                <div class="evidence">
                    <strong>Value:</strong> {{ finding.masked_value or finding.extracted_value[:100] }}{% if not finding.masked_value and finding.extracted_value|length > 100 %}...{% endif %}
                </div>
                {% endif %}

                <div class="location">
                    &#128205; {{ finding.evidence.file_url }}:{{ finding.evidence.line }}{% if finding.evidence.original_file_url or finding.evidence.original_line %} &nbsp;&middot;&nbsp; source: {{ finding.evidence.original_file_url or finding.evidence.file_url }}:{{ finding.evidence.original_line or finding.evidence.line }}{% endif %}
                </div>

                {% if v.snippet_html %}
                <div class="code-cap">CODE &nbsp;<span style="opacity:.7">(highlighted = the matched value that triggered this finding)</span></div>
                <div class="code">{{ v.snippet_html | safe }}</div>
                {% endif %}

                {% if finding.metadata.get('original_snippet') %}
                <div class="code-cap">ORIGINAL SOURCE (source-mapped)</div>
                <div class="code"><span class="cl"><span class="src">{{ finding.metadata.get('original_snippet') }}</span></span></div>
                {% endif %}

                <div class="tags">
                    {% for tag in finding.tags %}<span class="tag">{{ tag }}</span>{% endfor %}
                </div>
            </div>
            {% endfor %}
        </div>

        {% if report.clusters %}
        <div class="section">
            <h2>Clusters</h2>
            {% for cluster in report.clusters %}
            <div class="finding info">
                <div class="finding-header">
                    <span class="finding-title">{{ cluster.name }}</span>
                    <span class="badge info">{{ cluster.size }} findings</span>
                </div>
                <p>{{ cluster.description }}</p>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if report.errors %}
        <div class="section">
            <h2>Errors</h2>
            {% for error in report.errors %}
            <div class="finding low">{{ error }}</div>
            {% endfor %}
        </div>
        {% endif %}
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
            btn.innerHTML = hideNoise
                ? '👁 Show vendor / likely-FP noise'
                : '🙈 Hide vendor / likely-FP noise';
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
        report.compute_summary()
        # Redact secrets BEFORE rendering the template (objects) and dumping the embedded
        # JSON -- HTML previously never masked, leaking secrets in clear text.
        if self.mask_secrets:
            mask_secret_findings(report, self.secret_visible_chars)

        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        def _noise(f) -> bool:
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
            }
            for f in findings_sorted
        ]

        report_data = report.model_dump(mode="json", exclude_none=True)
        for asset in report_data.get("assets", []):
            asset.pop("content", None)
            asset.pop("sourcemap_content", None)
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
            report_json=report_json,
        )

