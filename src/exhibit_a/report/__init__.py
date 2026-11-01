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
from .sbom import analysis_for, generate_sbom, validate_sbom

__all__ = [
    "CWEDefinition",
    "CWE_TABLE",
    "analysis_for",
    "generate_sbom",
    "get_cwe",
    "generate_sarif",
    "render_html",
    "render_markdown",
    "sarif_level_from_severity",
    "security_severity_score",
    "severity_from_effect",
    "validate_sarif",
    "validate_sbom",
]
