"""
HTML report generator.
"""

from __future__ import annotations

import json
import re

from jinja2 import Environment

from bundleInspector.reporter.base import BaseReporter
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
                <div class="stat-value">{{ report.summary.findings_by_tier.get('P0', 0) + report.summary.findings_by_tier.get('P1', 0) }}</div>
                <div class="stat-label">Critical/High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ report.summary.total_clusters }}</div>
                <div class="stat-label">Clusters</div>
            </div>
        </div>

        <div class="section">
            <h2>Severity Distribution</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                {% for sev, count in report.summary.findings_by_severity.items() %}
                {% if count > 0 %}
                <tr>
                    <td><span class="badge {{ sev }}">{{ sev | upper }}</span></td>
                    <td>{{ count }}</td>
                </tr>
                {% endif %}
                {% endfor %}
            </table>
        </div>

        <div class="section">
            <h2>Findings</h2>
            <div class="filter-bar">
                <button class="filter-btn active" onclick="filterFindings(event, 'all')">All</button>
                <button class="filter-btn" onclick="filterFindings(event, 'critical')">Critical</button>
                <button class="filter-btn" onclick="filterFindings(event, 'high')">High</button>
                <button class="filter-btn" onclick="filterFindings(event, 'medium')">Medium</button>
                <button class="filter-btn" onclick="filterFindings(event, 'low')">Low</button>
            </div>

            {% for finding in findings_sorted %}
            <div class="finding {{ finding.severity.value }}" data-severity="{{ finding.severity.value }}">
                <div class="finding-header">
                    <span class="finding-title">{{ finding.title }}</span>
                    <div>
                        <span class="badge {{ finding.severity.value }}">{{ finding.severity.value | upper }}</span>
                        {% if finding.risk_tier %}
                        <span class="badge tier">{{ finding.risk_tier.value }}</span>
                        {% endif %}
                    </div>
                </div>
                <p>{{ finding.description }}</p>
                <div class="evidence">
                    <strong>Value:</strong> {{ finding.masked_value or finding.extracted_value[:100] }}{% if not finding.masked_value and finding.extracted_value|length > 100 %}...{% endif %}
                </div>
                {% if finding.metadata.get('matched_text') and finding.metadata.get('matched_text') != finding.extracted_value %}
                <div class="evidence">
                    <strong>Matched Text:</strong> {{ finding.metadata.get('matched_text')[:160] }}{% if finding.metadata.get('matched_text')|length > 160 %}...{% endif %}
                </div>
                {% endif %}
                <div class="location">
                    <strong>Location:</strong> {{ finding.evidence.file_url }}:{{ finding.evidence.line }}
                </div>
                {% if finding.evidence.original_file_url or finding.evidence.original_line %}
                <div class="location">
                    <strong>Original:</strong>
                    {{ finding.evidence.original_file_url or finding.evidence.file_url }}:{{ finding.evidence.original_line or finding.evidence.line }}
                </div>
                {% endif %}
                {% if finding.evidence.snippet %}
                <details>
                    <summary>Code Snippet</summary>
                    <pre><code>{{ finding.evidence.snippet }}</code></pre>
                </details>
                {% endif %}
                {% if finding.metadata.get('original_snippet') %}
                <details>
                    <summary>Original Source Snippet</summary>
                    <pre><code>{{ finding.metadata.get('original_snippet') }}</code></pre>
                </details>
                {% endif %}
                <div class="tags">
                    {% for tag in finding.tags %}
                    <span class="tag">{{ tag }}</span>
                    {% endfor %}
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
        function filterFindings(e, severity) {
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            e.target.classList.add('active');

            document.querySelectorAll('.finding[data-severity]').forEach(finding => {
                if (severity === 'all' || finding.dataset.severity === severity) {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
        }
    </script>
    <script id="bundleInspector-report-data" type="application/json">{{ report_json | safe }}</script>
</body>
</html>
"""


class HTMLReporter(BaseReporter):
    """Generate HTML reports."""

    name = "html"
    extension = ".html"

    def generate(self, report: Report) -> str:
        """Generate HTML report."""
        report.compute_summary()

        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        findings_sorted = sorted(
            report.findings,
            key=lambda f: (severity_order.get(f.severity, 5), -f.risk_score)
        )

        report_data = report.model_dump(mode="json", exclude_none=True)
        for asset in report_data.get("assets", []):
            asset.pop("content", None)
            asset.pop("sourcemap_content", None)
        report_json = re.sub(
            r"</script>",
            "<\\/script>",
            json.dumps(report_data, ensure_ascii=False),
            flags=re.IGNORECASE,
        )

        env = Environment(autoescape=True)
        template = env.from_string(HTML_TEMPLATE)
        return template.render(
            report=report,
            findings_sorted=findings_sorted,
            report_json=report_json,
        )

