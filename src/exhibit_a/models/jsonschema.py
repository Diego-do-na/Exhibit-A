"""A small, strict JSON Schema validator for untrusted model output.

It implements the subset of draft 2020-12 that the role schemas need. A keyword it does not
know raises UnsupportedSchemaError instead of being ignored, so a schema can never look
enforced while silently not being enforced.
"""

import re
from typing import Any

from .errors import SchemaValidationError, UnsupportedSchemaError

_ANNOTATIONS = {"$schema", "$id", "title", "description", "default", "examples"}
_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}


def _is_type(value: Any, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise UnsupportedSchemaError(f"unknown type {name!r}")


def validate(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    """Raise SchemaValidationError if `value` does not satisfy `schema`."""
    if not isinstance(schema, dict):
        raise UnsupportedSchemaError(f"schema at {path} must be an object")
    for key, rule in schema.items():
        if key in _ANNOTATIONS:
            continue
        _CHECKS.get(key, _unsupported(key))(value, rule, schema, path)


def _unsupported(key: str):
    def check(*_: Any) -> None:
        raise UnsupportedSchemaError(f"unsupported schema keyword {key!r}")

    return check


def _fail(path: str, message: str) -> None:
    raise SchemaValidationError(f"{path}: {message}")


def _type(value, rule, schema, path):
    names = rule if isinstance(rule, list) else [rule]
    if not all(n in _TYPES for n in names):
        raise UnsupportedSchemaError(f"unknown type in {names!r}")
    if not any(_is_type(value, n) for n in names):
        _fail(path, f"expected {' or '.join(names)}, got {type(value).__name__}")


def _enum(value, rule, schema, path):
    if not any(value == c and type(value) is type(c) for c in rule):
        _fail(path, f"value not in enum {rule!r}")


def _const(value, rule, schema, path):
    if not (value == rule and type(value) is type(rule)):
        _fail(path, f"expected constant {rule!r}")


def _properties(value, rule, schema, path):
    if not isinstance(value, dict):
        return
    for name, sub in rule.items():
        if name in value:
            validate(value[name], sub, f"{path}.{name}")


def _required(value, rule, schema, path):
    if isinstance(value, dict):
        for name in rule:
            if name not in value:
                _fail(path, f"missing required property {name!r}")


def _additional(value, rule, schema, path):
    if not isinstance(value, dict):
        return
    known = set(schema.get("properties", {}))
    for name in value:
        if name in known:
            continue
        if rule is False:
            _fail(path, f"unexpected property {name!r}")
        if isinstance(rule, dict):
            validate(value[name], rule, f"{path}.{name}")


def _items(value, rule, schema, path):
    if isinstance(value, list):
        for i, item in enumerate(value):
            validate(item, rule, f"{path}[{i}]")


def _bound(kind: str):
    def check(value, rule, schema, path):
        if kind in ("minimum", "maximum"):
            if not _is_type(value, "number"):
                return
            size, label = value, "value"
        else:
            size = len(value) if isinstance(value, (str, list)) else None
            if size is None:
                return
            label = "length"
        low = kind.startswith("min")
        if (low and size < rule) or (not low and size > rule):
            _fail(path, f"{label} {size} violates {kind} {rule}")

    return check


def _pattern(value, rule, schema, path):
    if isinstance(value, str) and re.search(rule, value) is None:
        _fail(path, f"string does not match pattern {rule!r}")


def _any_of(value, rule, schema, path):
    for sub in rule:
        try:
            validate(value, sub, path)
            return
        except SchemaValidationError:
            continue
    _fail(path, "value matches none of anyOf")


_CHECKS = {
    "type": _type,
    "enum": _enum,
    "const": _const,
    "properties": _properties,
    "required": _required,
    "additionalProperties": _additional,
    "items": _items,
    "minimum": _bound("minimum"),
    "maximum": _bound("maximum"),
    "minLength": _bound("minLength"),
    "maxLength": _bound("maxLength"),
    "minItems": _bound("minItems"),
    "maxItems": _bound("maxItems"),
    "pattern": _pattern,
    "anyOf": _any_of,
}
