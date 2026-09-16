"""Shared, autoescaped templates for the browser operator console."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from orgscan.security_context import current_auth, current_csrf


_TEMPLATES = Path(__file__).with_name("templates")
_ENV = Environment(
    loader=FileSystemLoader(_TEMPLATES),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render(template: str, **context: object) -> str:
    auth = current_auth.get()
    return _ENV.get_template(template).render(
        auth=auth if auth is not None and auth.authenticated else None,
        csrf_token=current_csrf.get(),
        **context,
    )
