"""Report rendering: dossier-style HTML + WeasyPrint PDF.

Aura direction (pending final lock): forensic audit dossier — bone white,
near-black ink, one signal-red accent, mono for numbers, grotesk headings,
hairline rules, strict grid. No gradients, no emoji, no filler copy.
"""
from jinja2 import Template

REPORT_CSS = """
:root {
  --ink: #111418;
  --paper: #f7f5f0;
  --muted: #5c6168;
  --rule: #d9d4ca;
  --accent: #c8102e;
  --crit: #c8102e; --high: #b45309; --med: #a16207; --low: #1d4ed8; --info: #5c6168;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 48px 56px;
  background: var(--paper); color: var(--ink);
  font-family: "Archivo", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-size: 13px; line-height: 1.5;
}
.mono, .score, td.num, .metric-value {
  font-family: "IBM Plex Mono", "SF Mono", Consolas, monospace;
}
header.dossier {
  border-bottom: 2px solid var(--ink);
  padding-bottom: 16px; margin-bottom: 28px;
  display: flex; justify-content: space-between; align-items: flex-end; gap: 24px;
}
header.dossier .kicker {
  font-size: 11px; letter-spacing: .14em; text-transform: uppercase;
  color: var(--muted); margin: 0 0 6px;
}
header.dossier h1 { font-size: 22px; margin: 0; font-weight: 700; letter-spacing: -0.01em; }
.score-block { text-align: right; }
.score {
  font-size: 64px; font-weight: 500; line-height: 1;
  letter-spacing: -0.03em; color: var(--ink);
}
.score.low { color: var(--accent); }
.score-label { font-size: 10px; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); }
section { margin: 0 0 28px; }
h2 {
  font-size: 11px; letter-spacing: .14em; text-transform: uppercase;
  color: var(--muted); border-bottom: 1px solid var(--rule);
  padding-bottom: 6px; margin: 0 0 12px; font-weight: 600;
}
.metrics { display: flex; gap: 32px; flex-wrap: wrap; }
.metric-label { font-size: 10px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.metric-value { font-size: 22px; font-weight: 500; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th {
  text-align: left; font-size: 10px; letter-spacing: .1em; text-transform: uppercase;
  color: var(--muted); border-bottom: 1px solid var(--ink); padding: 8px 10px; font-weight: 600;
}
td { padding: 8px 10px; border-bottom: 1px solid var(--rule); vertical-align: top; }
td.num { text-align: right; width: 48px; color: var(--muted); }
.sev { font-size: 10px; letter-spacing: .08em; text-transform: uppercase; font-weight: 700; }
.sev-critical { color: var(--crit); }
.sev-high { color: var(--high); }
.sev-medium { color: var(--med); }
.sev-low { color: var(--low); }
.sev-informational { color: var(--info); }
.bar-row { display: flex; align-items: center; gap: 12px; margin: 6px 0; }
.bar-label { width: 110px; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; }
.bar-track { flex: 1; height: 8px; background: #e8e4db; }
.bar-fill { height: 8px; background: var(--ink); }
.bar-fill.critical { background: var(--crit); }
.bar-count { width: 40px; text-align: right; font-family: "IBM Plex Mono", Consolas, monospace; font-size: 12px; }
.note {
  border-left: 3px solid var(--accent); padding: 10px 14px;
  background: #efece5; font-size: 12px; margin: 0;
}
.reco { margin: 0 0 8px; padding-left: 0; list-style: none; }
.reco li { border-bottom: 1px solid var(--rule); padding: 6px 0; }
.reco strong { font-weight: 600; }
footer {
  margin-top: 40px; border-top: 1px solid var(--rule);
  padding-top: 12px; font-size: 10px; color: var(--muted);
  display: flex; justify-content: space-between;
}
@media print {
  body { padding: 24px; background: white; }
  .no-break { break-inside: avoid; }
}
"""

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Assessment Report — {{ data.assessment.name }}</title>
<style>{{ css }}</style>
</head>
<body>
<header class="dossier">
  <div>
    <p class="kicker">Cloud Security Audit Tool · Assessment Report</p>
    <h1>{{ data.assessment.name }}</h1>
    <p class="mono" style="color:#5c6168;margin:6px 0 0;font-size:12px;">
      {{ data.assessment.date }} · status {{ data.assessment.status }} · engines {{ data.meta.engines }}
    </p>
  </div>
  <div class="score-block">
    <div class="score{% if data.assessment.security_score < 50 %} low{% endif %}">{{ "%.0f"|format(data.assessment.security_score) }}</div>
    <div class="score-label">Security score / 100</div>
  </div>
</header>

{% if data.ai_summary %}
<section class="no-break">
  <h2>Executive Summary</h2>
  <p>{{ data.ai_summary }}</p>
</section>
{% endif %}

<section class="no-break">
  <h2>Assessment Overview</h2>
  <p>{{ data.assessment.description or 'No description provided.' }}</p>
  <div class="metrics">
    <div><div class="metric-label">Findings</div><div class="metric-value">{{ data.assessment.total_findings }}</div></div>
    <div><div class="metric-label">Critical</div><div class="metric-value">{{ data.assessment.critical_count }}</div></div>
    <div><div class="metric-label">High</div><div class="metric-value">{{ data.assessment.high_count }}</div></div>
    <div><div class="metric-label">Medium</div><div class="metric-value">{{ data.assessment.medium_count }}</div></div>
    <div><div class="metric-label">Low</div><div class="metric-value">{{ data.assessment.low_count }}</div></div>
    <div><div class="metric-label">Info</div><div class="metric-value">{{ data.assessment.informational_count }}</div></div>
  </div>
</section>

<section class="no-break">
  <h2>Severity Breakdown</h2>
  {% for row in data.severity_bars %}
  <div class="bar-row">
    <div class="bar-label">{{ row.label }}</div>
    <div class="bar-track"><div class="bar-fill {{ row.label }}" style="width: {{ row.pct }}%"></div></div>
    <div class="bar-count">{{ row.count }}</div>
  </div>
  {% endfor %}
</section>

<section>
  <h2>Redundancy Note</h2>
  <p class="note">Engines {{ data.meta.engines }} produced {{ data.meta.raw_count }} raw findings;
  redundancy check removed {{ data.meta.redundancy_removed }} duplicates →
  <strong>{{ data.meta.deduped_count }} unique findings</strong> stored and reported.</p>
</section>

<section>
  <h2>Findings ({{ data.findings|length }})</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Severity</th><th>Category</th><th>Title</th><th>Engines</th><th>Status</th></tr>
    </thead>
    <tbody>
    {% for f in data.findings %}
      <tr>
        <td class="num">{{ loop.index }}</td>
        <td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
        <td>{{ f.category }}</td>
        <td>{{ f.title }}<br><span style="color:#5c6168;">{{ f.description|truncate(160) }}</span></td>
        <td class="mono" style="font-size:11px;">{{ f.engines }}</td>
        <td>{{ f.remediation_status }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</section>

<section>
  <h2>Recommendations</h2>
  <ul class="reco">
  {% for f in data.findings if f.recommendation %}
    <li><strong>{{ f.title }}.</strong> {{ f.recommendation }}</li>
  {% endfor %}
  </ul>
</section>

<footer>
  <span>Generated by Cloud Security Audit Tool</span>
  <span class="mono">{{ data.assessment.date }}</span>
</footer>
</body>
</html>"""


def build_report_data(assessment, findings, meta, ai_summary=''):
    total = len(findings)
    counts = {}
    for sev in ('critical', 'high', 'medium', 'low', 'informational'):
        counts[sev] = sum(1 for f in findings if f.severity == sev)
    max_count = max(counts.values()) if counts and max(counts.values()) > 0 else 1
    severity_bars = [
        {'label': sev, 'count': counts[sev], 'pct': max(2, int(counts[sev] / max_count * 100))}
        for sev in ('critical', 'high', 'medium', 'low', 'informational')
    ]
    return {
        'assessment': {
            'name': assessment.name,
            'description': assessment.description,
            'date': assessment.assessment_date.strftime('%Y-%m-%d %H:%M') if assessment.assessment_date else 'N/A',
            'status': assessment.status,
            'security_score': assessment.security_score or 0.0,
            'total_findings': assessment.total_findings or total,
            'critical_count': assessment.critical_count or counts['critical'],
            'high_count': assessment.high_count or counts['high'],
            'medium_count': assessment.medium_count or counts['medium'],
            'low_count': assessment.low_count or counts['low'],
            'informational_count': assessment.informational_count or counts['informational'],
        },
        'meta': meta,
        'severity_bars': severity_bars,
        'ai_summary': ai_summary or '',
        'findings': [
            {
                'id': f.id,
                'severity': f.severity,
                'category': f.category,
                'title': f.title,
                'description': f.description,
                'recommendation': f.recommendation or '',
                'remediation_status': f.remediation_status,
                'engines': f.engines or 'n/a',
                'resource': f.resource or '',
            }
            for f in findings
        ],
    }


def render_html(data):
    template = Template(REPORT_TEMPLATE)
    return template.render(data=data, css=REPORT_CSS)


def render_pdf(html_content):
    try:
        from weasyprint import HTML
    except Exception:
        return None, 'PDF engine (WeasyPrint) unavailable — reinstall dependencies (pip install -r requirements.txt) or use HTML/JSON.'
    try:
        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes, None
    except Exception as exc:
        return None, f'PDF rendering failed ({exc.__class__.__name__}) — use HTML/JSON instead.'
