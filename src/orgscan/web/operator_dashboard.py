"""Server-rendered operator cards. Policies live in DashboardService."""

from orgscan.web.render import render


def render_operator_queues(payload: dict, *, selected: str | None = None) -> str:
    return render("components/operator_overview.html", payload=payload, selected=selected)
