"""Prompts package for Agentic SRE investigation."""

from app.agents.prompts.investigation import (
    SYSTEM_INVESTIGATION_PROMPT,
    format_investigation_prompt,
)

__all__ = ["SYSTEM_INVESTIGATION_PROMPT", "format_investigation_prompt"]
