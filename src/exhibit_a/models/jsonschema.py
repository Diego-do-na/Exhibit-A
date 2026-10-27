"""A small, strict JSON Schema validator for untrusted model output.

It implements the subset of draft 2020-12 that the role schemas need. A keyword it does not
know raises UnsupportedSchemaError instead of being ignored, so a schema can never look
enforced while silently not being enforced. Malformed rules (for example ``properties``
given as a list, or ``minimum`` given as a string) also raise UnsupportedSchemaError:
they are bugs in the caller's schema, never something the value can satisfy.

Hostile values are rejected with SchemaValidationError, never mishandled: nesting depth,
string length, and container breadth are bounded so a malicious model reply cannot cause
unbounded recursion or runaway validation work, and non-finite numbers (NaN/Infinity,
which the JSON parser accepts) never validate.
"""

import math
import re
from typing import Any

from .errors import SchemaValidationError, UnsupportedSchemaError

_ANNOTATIONS = {"$schema", "$id", "title", "description", "default", "examples"}
_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}

# Defense-in-depth bounds for hostile values. Role payloads (suspicions, test
# sources, file patches) nest only a few levels deep and fit comfortably inside
# these limits; anything beyond them is rejected, not recursed into forever.
_MAX_DEPTH = 100
_MAX_STRING_LENGTH = 1_000_000
_MAX_PROPERTIES = 10_000
_MAX_ITEMS = 10_000


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
    _validate(value, schema, path, 0)


def _validate(value: Any, schema: dict[str, Any], path: str, depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise SchemaValidationError(f"{path}: value is nested too deeply")
    if isinstance(value, float) and not math.isfinite(value):
        raise SchemaValidationError(f"{path}: non-finite number is not allowed")
    if isinstance(value, str) and len(value) > _MAX_STRING_LENGTH:
        raise SchemaValidationError(
            f"{path}: string of length {len(value)} exceeds limit {_MAX_STRING_LENGTH}"
        )
    if isinstance(value, dict) and len(value) > _MAX_PROPERTIES:
        raise SchemaValidationError(
            f"{path}: object with {len(value)} properties exceeds limit {_MAX_PROPERTIES}"
        )
    if isinstance(value, list) and len(value) > _MAX_ITEMS:
        raise SchemaValidationError(
            f"{path}: array with {len(value)} items exceeds limit {_MAX_ITEMS}"
        )
    for key, rule in schema.items():
        if key in _ANNOTATIONS:
            continue
        check = _CHECKS.get(key)
        if check is None:
            raise UnsupportedSchemaError(f"unsupported schema keyword {key!r}")
        check(value, rule, schema, path, depth)


def _fail(path: str, message: str) -> None:
    raise SchemaValidationError(f"{path}: {message}")


def _type(value, rule, schema, path, depth):
    names = rule if isinstance(rule, list) else [rule]
    if not names or not all(isinstance(n, str) and n in _TYPES for n in names):
        raise UnsupportedSchemaError(f"unknown type in {rule!r}")
    if not any(_is_type(value, n) for n in names):
        _fail(path, f"expected {' or '.join(names)}, got {type(value).__name__}")


def _enum(value, rule, schema, path, depth):
    if not isinstance(rule, list):
        raise UnsupportedSchemaError(f"enum at {path} must be a list")
    if not any(value == c and type(value) is type(c) for c in rule):
        _fail(path, f"value not in enum {rule!r}")


def _const(value, rule, schema, path, depth):
    if not (value == rule and type(value) is type(rule)):
        _fail(path, f"expected constant {rule!r}")


def _properties(value, rule, schema, path, depth):
    if not isinstance(value, dict):
        return
    if not isinstance(rule, dict):
        raise UnsupportedSchemaError(f"properties at {path} must be an object")
    for name, sub in rule.items():
        if not isinstance(sub, dict):
            raise UnsupportedSchemaError(f"schema for property {name!r} at {path} must be an object")
        if name in value:
            _validate(value[name], sub, f"{path}.{name}", depth + 1)


def _required(value, rule, schema, path, depth):
    if not isinstance(value, dict):
        return
    if not isinstance(rule, list) or not all(isinstance(n, str) for n in rule):
        raise UnsupportedSchemaError(f"required at {path} must be a list of strings")
    for name in rule:
        if name not in value:
            _fail(path, f"missing required property {name!r}")


def _additional(value, rule, schema, path, depth):
    if not isinstance(value, dict):
        return
    if not isinstance(rule, bool) and not isinstance(rule, dict):
        raise UnsupportedSchemaError(
            f"additionalProperties at {path} must be a boolean or a schema object"
        )
    known = schema.get("properties", {})
    if not isinstance(known, dict):
        raise UnsupportedSchemaError(f"properties at {path} must be an object")
    for name in value:
        if name in known:
            continue
        if rule is False:
            _fail(path, f"unexpected property {name!r}")
        if isinstance(rule, dict):
            _validate(value[name], rule, f"{path}.{name}", depth + 1)


def _items(value, rule, schema, path, depth):
    if not isinstance(value, list):
        return
    if not isinstance(rule, dict):
        raise UnsupportedSchemaError(f"items at {path} must be a schema object")
    for i, item in enumerate(value):
        _validate(item, rule, f"{path}[{i}]", depth + 1)


def _bound(kind: str):
    def check(value, rule, schema, path, depth):
        if kind in ("minimum", "maximum"):
            if (
                isinstance(rule, bool)
                or not isinstance(rule, (int, float))
                or (isinstance(rule, float) and not math.isfinite(rule))
            ):
                raise UnsupportedSchemaError(f"{kind} at {path} must be a finite number")
            if not _is_type(value, "number"):
                return
            size, label = value, "value"
        else:
            if isinstance(rule, bool) or not isinstance(rule, int) or rule < 0:
                raise UnsupportedSchemaError(
                    f"{kind} at {path} must be a non-negative integer"
                )
            size = len(value) if isinstance(value, (str, list)) else None
            if size is None:
                return
            label = "length"
        low = kind.startswith("min")
        if (low and size < rule) or (not low and size > rule):
            _fail(path, f"{label} {size} violates {kind} {rule}")

    return check


def _pattern(value, rule, schema, path, depth):
    if not isinstance(rule, str):
        raise UnsupportedSchemaError(f"pattern at {path} must be a string")
    try:
        rx = re.compile(rule)
    except re.error as exc:
        raise UnsupportedSchemaError(f"invalid pattern at {path}: {exc}") from exc
    if isinstance(value, str) and rx.search(value) is None:
        _fail(path, f"string does not match pattern {rule!r}")


def _any_of(value, rule, schema, path, depth):
    if not isinstance(rule, list) or not rule or not all(isinstance(s, dict) for s in rule):
        raise UnsupportedSchemaError(f"anyOf at {path} must be a non-empty list of schemas")
    for sub in rule:
        try:
            _validate(value, sub, path, depth + 1)
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
