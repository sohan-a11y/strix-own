from __future__ import annotations

import os
from pathlib import Path

STRIX_COMMAND = os.environ.get("STRIX_EXECUTABLE", "strix")
DEFAULT_MODEL = os.environ.get("STRIX_ONECLICK_DEFAULT_MODEL", os.environ.get("STRIX_LLM", ""))
DATA_DIR = Path(os.environ.get("STRIX_ONECLICK_DATA_DIR", "~/.strix-oneclick")).expanduser()
WORK_DIR = Path(os.environ.get("STRIX_ONECLICK_WORK_DIR", str(Path.cwd()))).expanduser().resolve()
MAX_RUNTIME_SECONDS = int(os.environ.get("STRIX_ONECLICK_MAX_RUNTIME_SECONDS", "21600"))
ALLOW_PRIVATE_TARGETS = os.environ.get("STRIX_ONECLICK_ALLOW_PRIVATE_TARGETS", "false").lower() in {"1", "true", "yes"}
