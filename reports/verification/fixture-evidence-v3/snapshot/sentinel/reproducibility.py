"""Stable local metadata captured with each Sentinel assessment."""
from __future__ import annotations

import platform
import sys

from sentinel.config import settings


def capture_reproducibility() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "llm_provider": settings.llm_provider,
        "scout_model": settings.scout_model,
        "red_team_model": settings.red_team_model,
        "blue_team_model": settings.blue_team_model,
        "command_timeout_seconds": settings.command_timeout_seconds,
        "mythril_execution_timeout_seconds": settings.mythril_execution_timeout_seconds,
        "mythril_transaction_count": settings.mythril_transaction_count,
        "max_retries": settings.max_retries,
    }
