"""CWE mappings and deterministic severity calculation for proven vulnerabilities.

This module maps proven execution effects and vulnerability classes to standardized
Common Weakness Enumeration (CWE) identifiers and names, and derives finding severity
strictly from execution proof facts, never from model text.

Severity Derivation Rule:
------------------------
Severity is determined by the PROVEN effect observed by the oracle sandbox, never
from untrusted model hypotheses or text descriptions:

1. Execution effects ('canary_exec', 'exec') and SQL injection ('sql', 'canary_sql'):
   - 'critical': The exploit achieved command/code execution or arbitrary SQL execution
     through an admitted application entry point with verified provenance.
   - 'high': Execution effect proven, but without an external/declared entry point or
     unauthenticated provenance.
2. Write effects ('canary_write', 'write'):
   - 'high': The exploit wrote or modified a file outside the restricted sandbox directory
     (arbitrary file write / zip slip). Unauthorized file modification in the application
     root can overwrite executable assets or configuration.
3. Read effects ('canary_read', 'read'):
   - 'high': The exploit read a sensitive file (outside the restricted directory) reached
     through an admitted entry point with authenticated provenance.
   - 'medium': Read effect proven without a declared entry point or read-only probe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class CWEDefinition:
    """Standard identifier, title and description for a CWE."""

    cwe_id: str
    name: str
    description: str = ""


# Canonical CWE definitions
CWE_22 = CWEDefinition(
    cwe_id="CWE-22",
    name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    description="The product uses external input to construct a pathname intended to identify a file or directory within a restricted parent directory, but the pathname resolves to a location outside the boundary.",
)

CWE_73 = CWEDefinition(
    cwe_id="CWE-73",
    name="External Control of File Name or Path",
    description="The software allows user input to control or influence paths used in filesystem operations, potentially allowing arbitrary file creation, overwrite, or modification.",
)

CWE_78 = CWEDefinition(
    cwe_id="CWE-78",
    name="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    description="The software constructs all or part of an OS command using externally-influenced input, allowing arbitrary system commands to be executed.",
)

CWE_89 = CWEDefinition(
    cwe_id="CWE-89",
    name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    description="The software constructs all or part of an SQL command using externally-influenced input, allowing arbitrary database operations.",
)

CWE_95 = CWEDefinition(
    cwe_id="CWE-95",
    name="Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    description="The software receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before dynamic evaluation (eval, exec).",
)

CWE_502 = CWEDefinition(
    cwe_id="CWE-502",
    name="Deserialization of Untrusted Data",
    description="The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid or safe to execute.",
)


def _normalize(value: str) -> str:
    """Normalize effect or vuln_class tokens for table lookup."""
    return value.strip().lower().replace("-", "_").replace(" ", "_")


#: Primary table mapping (normalized_effect, normalized_vuln_class) -> CWEDefinition
CWE_TABLE: dict[tuple[str, str], CWEDefinition] = {
    # Path traversal (read)
    ("canary_read", "path_traversal"): CWE_22,
    ("read", "path_traversal"): CWE_22,

    # Arbitrary file write / archive-extraction path traversal (zip slip) -> CWE-73 or CWE-22
    ("canary_write", "path_traversal_write"): CWE_22,
    ("canary_write", "archive_extraction_path_traversal"): CWE_22,
    ("canary_write", "path_traversal"): CWE_22,
    ("canary_write", "arbitrary_file_write"): CWE_73,
    ("write", "path_traversal_write"): CWE_22,
    ("write", "archive_extraction_path_traversal"): CWE_22,
    ("write", "path_traversal"): CWE_22,
    ("write", "arbitrary_file_write"): CWE_73,

    # OS command injection
    ("canary_exec", "command_injection"): CWE_78,
    ("canary_exec", "os_command_injection"): CWE_78,
    ("exec", "command_injection"): CWE_78,
    ("exec", "os_command_injection"): CWE_78,

    # Dynamic eval injection
    ("canary_exec", "code_injection"): CWE_95,
    ("canary_exec", "eval_injection"): CWE_95,
    ("exec", "code_injection"): CWE_95,
    ("exec", "eval_injection"): CWE_95,

    # Unsafe deserialization
    ("canary_exec", "insecure_deserialization"): CWE_502,
    ("canary_exec", "unsafe_deserialization"): CWE_502,
    ("exec", "insecure_deserialization"): CWE_502,
    ("exec", "unsafe_deserialization"): CWE_502,

    # SQL injection
    ("canary_sql", "sql_injection"): CWE_89,
    ("sql", "sql_injection"): CWE_89,
    ("canary_exec", "sql_injection"): CWE_89,
    ("exec", "sql_injection"): CWE_89,
}


def get_cwe(effect: str, vuln_class: str) -> CWEDefinition:
    """Find the CWE definition for a given effect and vulnerability class.

    Performs exact normalized lookup in CWE_TABLE first, then applies heuristic
    matching on standard vulnerability class names if an exact tuple is not present.
    """
    norm_effect = _normalize(effect)
    norm_class = _normalize(vuln_class)

    # 1. Exact lookup in table
    entry = CWE_TABLE.get((norm_effect, norm_class))
    if entry is not None:
        return entry

    # Try stripped canary_ prefix
    bare_effect = norm_effect[7:] if norm_effect.startswith("canary_") else norm_effect
    entry = CWE_TABLE.get((bare_effect, norm_class))
    if entry is not None:
        return entry

    # 2. Heuristic fallback based on vulnerability class keywords
    if "sql" in norm_class or "sql" in norm_effect:
        return CWE_89
    if "command" in norm_class:
        return CWE_78
    if "eval" in norm_class or "code_injection" in norm_class:
        return CWE_95
    if "deserializ" in norm_class:
        return CWE_502
    if "archive" in norm_class or "traversal" in norm_class:
        return CWE_22
    if "file_write" in norm_class or norm_class == "write":
        return CWE_73

    # 3. Fallback based on effect
    if bare_effect == "write":
        return CWE_73
    if bare_effect in ("exec", "command"):
        return CWE_78
    return CWE_22


def severity_from_effect(
    effect: str,
    *,
    vuln_class: str | None = None,
    provenance_ok: bool = True,
    has_entry_point: bool = True,
) -> str:
    """Derive severity strictly from execution proof facts, never from model text.

    Args:
        effect: The proven effect (e.g. 'canary_read', 'canary_write', 'canary_exec', 'sql').
        vuln_class: Optional vulnerability class string.
        provenance_ok: Whether the oracle authenticated application provenance.
        has_entry_point: Whether a declared or discovered application entry point was reached.

    Returns:
        One of 'critical', 'high', 'medium', 'low'.
    """
    eff = _normalize(effect)
    if eff.startswith("canary_"):
        eff = eff[len("canary_"):]

    cls = _normalize(vuln_class) if vuln_class else ""

    # Execution (command/eval/deserialization) and SQL
    if eff in ("exec", "sql") or "sql" in cls or "command" in cls or "eval" in cls:
        if provenance_ok and has_entry_point:
            return "critical"
        return "high"

    # Arbitrary file write / zip slip
    if eff == "write" or "write" in cls:
        return "high"

    # File read / path traversal
    if eff == "read" or "read" in cls or "traversal" in cls:
        if provenance_ok and has_entry_point:
            return "high"
        return "medium"

    return "medium"


def sarif_level_from_severity(severity: str) -> str:
    """Map Exhibit A severity string to SARIF 2.1.0 result level ('error', 'warning', 'note')."""
    sev = severity.lower().strip()
    if sev in ("critical", "high"):
        return "error"
    if sev == "medium":
        return "warning"
    if sev in ("low", "note", "informational"):
        return "note"
    return "none"


def security_severity_score(severity: str) -> str:
    """Map Exhibit A severity string to a CVSS-like score string for GitHub Code Scanning."""
    sev = severity.lower().strip()
    if sev == "critical":
        return "9.0"
    if sev == "high":
        return "7.5"
    if sev == "medium":
        return "5.0"
    if sev == "low":
        return "2.5"
    return "0.0"
