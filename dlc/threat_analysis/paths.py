"""Shared paths for the offline threat-analysis DLC."""

from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _path_from_env(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    if not value:
        return default
    path = Path(value).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


VAR_ROOT = _path_from_env("NSL_VAR_DIR", PROJECT_ROOT / "var")
LOG_DIR = _path_from_env("NSL_ANALYSIS_LOG_DIR", VAR_ROOT / "logs")
DATA_DIR = _path_from_env("NSL_ANALYSIS_DATA_DIR", VAR_ROOT / "analysis_data")
OUTPUT_DIR = _path_from_env("NSL_ANALYSIS_OUTPUT_DIR", VAR_ROOT / "analysis_output")
BLACKLIST_FILE = _path_from_env("NSL_ANALYSIS_BLACKLIST", VAR_ROOT / "black_ip.conf")
ALLOWLIST_FILE = _path_from_env(
    "NSL_ANALYSIS_ALLOWLIST",
    VAR_ROOT / "analysis_allowlist.txt",
)
NGINX_SOURCE = _path_from_env("NSL_ANALYSIS_NGINX", VAR_ROOT / "nginx.conf")
