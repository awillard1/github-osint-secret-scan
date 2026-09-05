from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from orgscan.db import create_session_factory, init_db
from orgscan.reporting import build_summary, finding_rows
from orgscan.repositories import Storage


class OrgscanApiService:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def handle(self, path: str) -> tuple[int, dict[str, object]]:
        init_db(self.database_url)
        session_factory = create_session_factory(self.database_url)
        parsed = urlparse(path)
        route = parsed.path
        params = parse_qs(parsed.query)
        with session_factory() as session:
            storage = Storage(session)
            if route == "/health":
                return 200, {"status": "ok"}
            if route == "/summary":
                return 200, build_summary(storage)
            if route == "/findings":
                limit = int(params.get("limit", ["50"])[0])
                return 200, {"findings": finding_rows(storage, limit=limit)}
            if route == "/scheduled-scans":
                scans = [
                    {
                        "id": scan.id,
                        "target_type": scan.target_type,
                        "target_value": scan.target_value,
                        "scanner_name": scan.scanner_name,
                        "cadence": scan.cadence,
                        "enabled": scan.enabled,
                        "next_run_at": scan.next_run_at.isoformat(),
                    }
                    for scan in storage.list_scheduled_scans()
                ]
                return 200, {"scheduled_scans": scans}
        return 404, {"error": f"Unknown route: {route}"}


class _Handler(BaseHTTPRequestHandler):
    service: OrgscanApiService

    def do_GET(self) -> None:  # noqa: N802
        status, payload = self.service.handle(self.path)
        body = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve_api(database_url: str, host: str = "127.0.0.1", port: int = 8000) -> None:
    service = OrgscanApiService(database_url)
    handler = type("OrgscanHandler", (_Handler,), {"service": service})
    server = ThreadingHTTPServer((host, port), handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
