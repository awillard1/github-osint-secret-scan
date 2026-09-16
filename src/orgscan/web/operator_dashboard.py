"""Escaped server-rendered operator cards. Policies live in DashboardService."""
import html


def render_operator_queues(payload: dict, *, selected: str | None = None) -> str:
    sections = []
    for name, queue in payload["queues"].items():
        if selected and selected != name:
            continue
        rows = "".join(
            f'<li><a href="{html.escape(row["href"], quote=True)}">{html.escape(str(row["label"]))}</a> '
            f'— {html.escape(str(row["state"]))}'
            + (f' · risk {row["risk_score"]} · {html.escape(row["severity"])} / {html.escape(row["confidence"])}' if "risk_score" in row else "")
            + '</li>' for row in queue["items"]
        ) or '<li>No items in this queue.</li>'
        link = f'/dashboard/queues/{name}?days={payload["days"]}'
        sections.append(f'<section><h3><a href="{link}">{queue["label"]}</a> ({queue["count"]})</h3><ul>{rows}</ul></section>')
    return (f'<section aria-label="Operator overview"><h2>Operator overview</h2>'
            f'<p>New observations cover the past {payload["days"]} days. Other queues show current state.</p>'
            '<div class="grid">'+''.join(sections)+'</div></section>')
