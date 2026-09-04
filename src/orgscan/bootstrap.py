from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import venv
from pathlib import Path

from orgscan.config import Settings

REQUIRED_COMMANDS = ("git", "curl", "openssl")
OPTIONAL_COMMANDS = ("jq", "gitleaks", "trufflehog")
OPTIONAL_INSTALL_NOTES = {
    "jq": "Package manager install is usually sufficient.",
    "gitleaks": "Prefer the official release binary or install script rather than OS packages for current versions.",
    "trufflehog": "Prefer the official upstream installation method rather than OS packages for current versions.",
}


def detect_package_manager() -> str | None:
    for candidate in ("apt", "dnf", "yum", "brew", "pacman"):
        if shutil.which(candidate):
            return candidate
    return None


def command_status(command: str) -> bool:
    return shutil.which(command) is not None


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

    return {
        "platform": platform.platform(),
        "package_manager": package_manager,
        "required": {command: command_status(command) for command in REQUIRED_COMMANDS},
        "optional": {command: command_status(command) for command in OPTIONAL_COMMANDS},
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
