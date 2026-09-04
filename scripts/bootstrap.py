from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from orgscan.bootstrap import bootstrap
from orgscan.config import Settings
from orgscan.db import init_db


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap local orgscan development dependencies.")
    parser.add_argument("--verify-only", action="store_true", help="Only verify dependencies and print next steps.")
    parser.add_argument("--install-only", action="store_true", help="Create .venv and install Python dependencies without initializing the database.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    settings = Settings()
    details = bootstrap(
        settings,
        create_venv=not args.verify_only,
        install_dev=not args.verify_only,
        verify_only=args.verify_only,
    )
    database_initialized = False
    if not args.verify_only and not args.install_only:
        init_db(settings.database_url)
        database_initialized = True
    print(json.dumps({**details, "database_initialized": database_initialized}, indent=2, default=str))
