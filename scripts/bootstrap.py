from __future__ import annotations

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


if __name__ == "__main__":
    settings = Settings()
    details = bootstrap(settings, create_venv=True, install_dev=True)
    init_db(settings.database_url)
    print(json.dumps({**details, "database_initialized": True}, indent=2, default=str))
