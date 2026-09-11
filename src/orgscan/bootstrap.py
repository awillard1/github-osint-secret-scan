from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import venv
from pathlib import Path

from orgscan.config import Settings
from orgscan.scanners import get_registry
from orgscan.services.scanner_service import scanner_inventory

REQUIRED_COMMANDS = ("git", "curl", "openssl")
OPTIONAL_COMMANDS = (
    "jq",
    "redis-server",
    "gitleaks",
    "detect-secrets",
    "semgrep",
    "trufflehog",
    "yara",
    "rg",
    "subfinder",
    "httpx",
    "whois",
)
OPTIONAL_INSTALL_NOTES = {
    "jq": "Package manager install is usually sufficient.",
    "redis-server": "Install Redis locally or point ORGSCAN_REDIS_URL at a reachable Redis service to enable queue workers.",
    "gitleaks": "Prefer the official release binary or install script rather than OS packages for current versions.",
    "detect-secrets": "Install the Yelp detect-secrets CLI to add an additional baseline-oriented secret scanner.",
    "semgrep": "Prefer pipx or the official installation method if you plan to use Semgrep locally.",
    "trufflehog": "Prefer the official upstream installation method rather than OS packages for current versions.",
    "yara": "Install the YARA CLI to enable rule-based artifact and secret matching.",
    "rg": "Install ripgrep to enable fast heuristic scanning for internal hostnames and org-specific indicators.",
    "subfinder": "Use ProjectDiscovery's official release or package instructions for passive subdomain discovery.",
    "httpx": "Use ProjectDiscovery's official release or package instructions for HTTP probing and metadata collection.",
    "whois": "Install the standard whois client package to enable registrar and nameserver enrichment.",
}
OPTIONAL_TOOL_METADATA = {
    "jq": {
        "category": "operator",
        "description": "Formats and filters JSON output from orgscan commands and APIs.",
        "env_var": None,
        "settings_attr": None,
    },
    "redis-server": {
        "category": "queue",
        "description": "Optional queue backend for scheduled scan workers.",
        "env_var": "ORGSCAN_REDIS_URL",
        "settings_attr": None,
    },
    "subfinder": {
        "category": "provider",
        "description": "Passive subdomain discovery for ProjectDiscovery enrichment.",
        "env_var": "ORGSCAN_SUBFINDER_BINARY",
        "settings_attr": "subfinder_binary",
    },
    "httpx": {
        "category": "provider",
        "description": "HTTP probing and metadata enrichment for discovered hosts.",
        "env_var": "ORGSCAN_HTTPX_BINARY",
        "settings_attr": "httpx_binary",
    },
    "whois": {
        "category": "provider",
        "description": "Registrar and nameserver enrichment for tracked domains.",
        "env_var": "ORGSCAN_WHOIS_BINARY",
        "settings_attr": "whois_binary",
    },
}


def detect_package_manager() -> str | None:
    for candidate in ("apt", "dnf", "yum", "brew", "pacman"):
        if shutil.which(candidate):
            return candidate
    return None


def command_status(command: str) -> bool:
    return shutil.which(command) is not None


def optional_tool_inventory(settings: Settings) -> list[dict[str, object]]:
    tools: list[dict[str, object]] = []
    scanner_tools = {}
    for row in scanner_inventory(settings):
        metadata = row["metadata"]
        binary = metadata["binary"]
        if binary and binary not in REQUIRED_COMMANDS:
            scanner_tools[binary] = {
                "name": binary,
                "category": "scanner",
                "description": metadata["description"] or metadata["display_name"],
                "configured_command": row["configured_command"],
                "env_var": metadata["binary_env_var"],
                "installed": row["readiness"]["binary_path"] is not None,
                "install_note": OPTIONAL_INSTALL_NOTES.get(binary, "Configure the scanner's declared requirements."),
                "ready": row["readiness"]["ready"],
                "status": row["readiness"]["status"],
            }
    for command in dict.fromkeys((*OPTIONAL_COMMANDS, *scanner_tools)):
        if command in scanner_tools:
            tools.append(scanner_tools[command])
            continue
        metadata = OPTIONAL_TOOL_METADATA.get(command, {})
        configured_value = getattr(settings, str(metadata.get("settings_attr")), None) if metadata.get("settings_attr") else command
        resolved_command = str(configured_value or command)
        tools.append(
            {
                "name": command,
                "category": metadata.get("category", "optional"),
                "description": metadata.get("description", ""),
                "configured_command": resolved_command,
                "env_var": metadata.get("env_var"),
                "installed": command_status(resolved_command),
                "install_note": OPTIONAL_INSTALL_NOTES.get(command, ""),
            }
        )
    return tools


def recommended_install_command(package_manager: str | None, commands: tuple[str, ...]) -> str:
    package_list = " ".join(commands)
    if package_manager == "apt":
        return f"sudo apt update && sudo apt install -y {package_list}"
    if package_manager == "brew":
        return f"brew install {package_list}"
    if package_manager == "dnf":
        return f"sudo dnf install -y {package_list}"
    if package_manager == "yum":
        return f"sudo yum install -y {package_list}"
    if package_manager == "pacman":
        return f"sudo pacman -S --needed {package_list}"
    return f"Install manually: {package_list}"


def bootstrap(
    settings: Settings,
    create_venv: bool = False,
    install_dev: bool = False,
    verify_only: bool = False,
) -> dict[str, object]:
    settings.ensure_data_dir()
    package_manager = detect_package_manager()
    repo_root = Path(__file__).resolve().parents[2]
    venv_path = repo_root / ".venv"

    if create_venv and not verify_only and not venv_path.exists():
        venv.EnvBuilder(with_pip=True).create(venv_path)

    install_result = None
    if install_dev and not verify_only:
        python_bin = venv_path / "bin" / "python"
        if not python_bin.exists():
            python_bin = Path(sys.executable)
        install_result = subprocess.run(
            [str(python_bin), "-m", "pip", "install", "-e", ".[dev]"],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
        )

    tools = optional_tool_inventory(settings)
    return {
        "platform": platform.platform(),
        "package_manager": package_manager,
        "required": {command: command_status(command) for command in REQUIRED_COMMANDS},
        "optional": {str(tool["name"]): tool["installed"] for tool in tools},
        "optional_tools": tools,
        "scanner_readiness": scanner_inventory(settings),
        "scanner_registry_warnings": list(get_registry().warnings),
        "recommended_install": recommended_install_command(package_manager, REQUIRED_COMMANDS),
        "optional_install_notes": OPTIONAL_INSTALL_NOTES,
        "venv_path": str(venv_path),
        "venv_exists": venv_path.exists(),
        "install_returncode": None if install_result is None else install_result.returncode,
        "mode": "verify-only" if verify_only else "install",
        "database_url": settings.database_url,
        "data_dir": str(settings.data_dir),
        "next_steps": [
            "Create and activate the virtual environment." if not venv_path.exists() else "Activate the existing virtual environment.",
            "Install the package with development dependencies." if not verify_only else "Install missing dependencies, then rerun verification.",
            "Run `orgscan init-db` or `orgscan setup --init-db` to initialize local storage.",
        ],
    }
