"""Readable, deterministic reports for packaged Exhibit A findings."""

from .cwe import (
    CWEDefinition,
    CWE_TABLE,
    get_cwe,
    sarif_level_from_severity,
    security_severity_score,
    severity_from_effect,
)
from .report import render_html, render_markdown
from .sarif import generate_sarif, validate_sarif

__all__ = [
    "CWEDefinition",
    "CWE_TABLE",
    "get_cwe",
    "generate_sarif",
    "render_html",
    "render_markdown",
    "sarif_level_from_severity",
    "security_severity_score",
    "severity_from_effect",
    "validate_sarif",
]
