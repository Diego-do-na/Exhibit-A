"""Compatibility shim for the unified coverage generator."""

from .coverage_matrix import (
    BEGIN_MARKER,
    CASE_CWE,
    CLASS_CWE,
    CORPUS,
    DOC,
    END_MARKER,
    main,
    render,
    update_document,
)

__all__ = [
    "BEGIN_MARKER",
    "CASE_CWE",
    "CLASS_CWE",
    "CORPUS",
    "DOC",
    "END_MARKER",
    "main",
    "render",
    "update_document",
]


if __name__ == "__main__":
    main()
