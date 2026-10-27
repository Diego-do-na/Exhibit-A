"""Adversarial tests for the strict JSON Schema validator.

Model output is untrusted data: every test below feeds the validator something
hostile (deep nesting, wrong types, extra keys, huge strings, malformed schemas)
and requires a clean ModelError out, never a crash, hang, or silent pass.
"""

import math

import pytest

from exhibit_a.models.errors import SchemaValidationError, UnsupportedSchemaError
from exhibit_a.models.jsonschema import (
    _MAX_ITEMS,
    _MAX_PROPERTIES,
    _MAX_STRING_LENGTH,
    validate,
)


def nest_list(depth, leaf=0):
    value = leaf
    for _ in range(depth):
        value = [value]
    return value


def nest_list_schema(depth):
    schema = {"type": "integer"}
    for _ in range(depth):
        schema = {"type": "array", "items": schema}
    return schema


def test_deeply_nested_value_is_rejected_not_recursed_forever():
    # A hostile nesting far beyond any real role payload must fail validation
    # instead of raising RecursionError or hanging.
    with pytest.raises(SchemaValidationError, match="nested too deeply"):
        validate(nest_list(500), nest_list_schema(500))


def test_moderate_nesting_still_validates():
    validate(nest_list(10), nest_list_schema(10))


def test_deeply_nested_objects_are_rejected():
    value, schema = {"a": 1}, {"type": "integer"}
    for _ in range(500):
        value, schema = {"a": value}, {
            "type": "object",
            "properties": {"a": schema},
            "additionalProperties": False,
        }
    with pytest.raises(SchemaValidationError, match="nested too deeply"):
        validate(value, schema)


@pytest.mark.parametrize("bad_number", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_never_validate(bad_number):
    with pytest.raises(SchemaValidationError, match="non-finite"):
        validate(bad_number, {"type": "number"})
    with pytest.raises(SchemaValidationError, match="non-finite"):
        validate(bad_number, {"type": "number", "minimum": 0})
    with pytest.raises(SchemaValidationError, match="non-finite"):
        validate({"score": bad_number}, {
            "type": "object",
            "properties": {"score": {"type": "number"}},
        })


def test_huge_string_is_rejected():
    with pytest.raises(SchemaValidationError, match="exceeds limit"):
        validate("x" * (_MAX_STRING_LENGTH + 1), {"type": "string"})
    with pytest.raises(SchemaValidationError, match="exceeds limit"):
        validate("x" * (_MAX_STRING_LENGTH + 1), {"type": "string", "maxLength": 10**9})


def test_huge_string_nested_inside_object_is_rejected():
    big = "y" * (_MAX_STRING_LENGTH + 1)
    with pytest.raises(SchemaValidationError, match="exceeds limit"):
        validate({"test_source": big}, {
            "type": "object",
            "properties": {"test_source": {"type": "string"}},
        })


def test_giant_object_and_array_are_rejected():
    with pytest.raises(SchemaValidationError, match="exceeds limit"):
        validate({f"k{i}": i for i in range(_MAX_PROPERTIES + 1)}, {"type": "object"})
    with pytest.raises(SchemaValidationError, match="exceeds limit"):
        validate([0] * (_MAX_ITEMS + 1), {"type": "array", "items": {"type": "integer"}})


@pytest.mark.parametrize(
    "value", [True, 1, 1.5, "x", [], None]
)
def test_wrong_types_rejected_for_object(value):
    schema = {"type": "object", "properties": {}, "additionalProperties": False}
    with pytest.raises(SchemaValidationError):
        validate(value, schema)


@pytest.mark.parametrize(
    "type_name,value",
    [
        ("integer", True),
        ("integer", 1.0),
        ("integer", "1"),
        ("number", True),
        ("number", "1"),
        ("string", 1),
        ("string", None),
        ("boolean", 1),
        ("boolean", "true"),
        ("array", {}),
        ("null", 0),
        ("null", False),
    ],
)
def test_strict_scalar_types(type_name, value):
    with pytest.raises(SchemaValidationError):
        validate(value, {"type": type_name})


def test_bool_is_not_an_integer_or_number():
    with pytest.raises(SchemaValidationError):
        validate(True, {"type": "integer", "minimum": 0})


def test_extra_keys_rejected_where_contract_forbids_them():
    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "required": ["verdict"],
        "additionalProperties": False,
    }
    with pytest.raises(SchemaValidationError, match="unexpected property"):
        validate({"verdict": "yes", "__proto__": 1}, schema)
    with pytest.raises(SchemaValidationError, match="unexpected property"):
        validate({"verdict": "yes", "extra": {"nested": True}}, schema)


def test_nested_extra_keys_rejected():
    schema = {
        "type": "object",
        "properties": {
            "location": {
                "type": "object",
                "properties": {"file": {"type": "string"}},
                "required": ["file"],
                "additionalProperties": False,
            }
        },
        "required": ["location"],
        "additionalProperties": False,
    }
    with pytest.raises(SchemaValidationError, match="unexpected property"):
        validate({"location": {"file": "a.py", "line": 1}}, schema)


def test_additional_properties_schema_is_enforced():
    schema = {"type": "object", "additionalProperties": {"type": "string"}}
    validate({"a": "ok"}, schema)
    with pytest.raises(SchemaValidationError):
        validate({"a": 1}, schema)


def test_additional_properties_true_allows_extras():
    schema = {"type": "object", "properties": {"a": {"type": "string"}}}
    validate({"a": "x", "whatever": [1, 2]}, schema)


@pytest.mark.parametrize(
    "keyword,schema,value",
    [
        ("$ref", {"$ref": "#/defs/x"}, {}),
        ("allOf", {"allOf": [{"type": "string"}]}, "anything"),
        ("oneOf", {"oneOf": [{"type": "string"}]}, "anything"),
        ("not", {"not": {"type": "string"}}, "anything"),
        ("if", {"if": {"type": "string"}}, "anything"),
        ("prefixItems", {"prefixItems": [{"type": "string"}]}, ["anything"]),
        ("contains", {"contains": {"type": "string"}}, ["anything"]),
        ("patternProperties", {"patternProperties": {"^x": {"type": "string"}}}, {}),
        ("propertyNames", {"propertyNames": {"type": "string"}}, {}),
        ("unevaluatedItems", {"unevaluatedItems": False}, []),
        ("dependentSchemas", {"dependentSchemas": {"a": {"type": "string"}}}, {}),
        ("format", {"type": "string", "format": "date-time"}, "anything"),
        ("multipleOf", {"type": "integer", "multipleOf": 2}, 4),
        ("uniqueItems", {"type": "array", "uniqueItems": True}, [1, 1]),
        ("exclusiveMinimum", {"type": "number", "exclusiveMinimum": 0}, 5),
    ],
)
def test_unsupported_keywords_raise_instead_of_being_ignored(keyword, schema, value):
    with pytest.raises(UnsupportedSchemaError):
        validate(value, schema)


@pytest.mark.parametrize(
    "schema,value",
    [
        ({"properties": []}, {}),
        ({"properties": {"a": "string"}}, {"a": "x"}),
        ({"required": "verdict"}, {"verdict": "yes"}),
        ({"required": [1]}, {"1": "x"}),
        ({"additionalProperties": "no"}, {"a": 1}),
        ({"additionalProperties": 0}, {"a": 1}),
        ({"items": [{"type": "string"}]}, ["x"]),
        ({"items": True}, [1]),
        ({"type": 42}, 1),
        ({"type": {"name": "string"}}, "x"),
        ({"type": []}, "x"),
        ({"type": ["string", 42]}, "x"),
        ({"type": ["string", "fancy"]}, "x"),
        ({"enum": "yes"}, "yes"),
        ({"enum": {"a": 1}}, "a"),
        ({"minimum": "0"}, 5),
        ({"maximum": None}, 5),
        ({"minLength": -1}, "x"),
        ({"minLength": 1.5}, "x"),
        ({"minLength": True}, "x"),
        ({"maxItems": "3"}, [1]),
        ({"pattern": 42}, "abc"),
        ({"pattern": "(["}, "abc"),
        ({"anyOf": {}}, 1),
        ({"anyOf": []}, 1),
        ({"anyOf": ["string"]}, "x"),
        (True, 1),
        ("string", "x"),
    ],
)
def test_malformed_schemas_raise_unsupported(schema, value):
    with pytest.raises(UnsupportedSchemaError):
        validate(value, schema)


def test_malformed_rule_never_silently_passes():
    # Regression: required-as-string used to iterate characters and pass.
    with pytest.raises(UnsupportedSchemaError):
        validate({"a": 1}, {"type": "object", "required": "a"})
    # Regression: additionalProperties-as-string used to allow everything.
    with pytest.raises(UnsupportedSchemaError):
        validate({"evil": 1}, {"type": "object", "additionalProperties": "no"})


def test_unknown_type_name_raises_unsupported():
    with pytest.raises(UnsupportedSchemaError):
        validate("x", {"type": "fancy"})


def test_annotations_are_ignored():
    validate("x", {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.com/x",
        "title": "t",
        "description": "d",
        "default": "y",
        "examples": ["x"],
        "type": "string",
    })


def test_anyOf_tries_branches_and_reports_cleanly():
    schema = {"anyOf": [{"type": "string"}, {"type": "integer", "minimum": 0}]}
    validate("ok", schema)
    validate(3, schema)
    with pytest.raises(SchemaValidationError, match="none of anyOf"):
        validate(-1, schema)


def test_anyOf_does_not_swallow_schema_bugs():
    # "x" would satisfy the first branch, so use a value that reaches the
    # broken branch; its UnsupportedSchemaError must propagate, not be
    # treated as "branch did not match".
    with pytest.raises(UnsupportedSchemaError):
        validate(1, {"anyOf": [{"type": "string"}, {"bogus": True}]})


def test_bounds_and_patterns_still_enforced():
    validate("abc123", {"type": "string", "pattern": "^[a-z]+[0-9]+$", "minLength": 3, "maxLength": 10})
    with pytest.raises(SchemaValidationError):
        validate("ABC", {"type": "string", "pattern": "^[a-z]+$"})
    with pytest.raises(SchemaValidationError):
        validate("ab", {"type": "string", "minLength": 3})
    with pytest.raises(SchemaValidationError):
        validate([1, 2], {"type": "array", "maxItems": 1})
    with pytest.raises(SchemaValidationError):
        validate(5, {"type": "integer", "minimum": 0, "maximum": 4})


def test_pattern_applies_only_to_strings():
    validate(123, {"pattern": "^[a-z]+$"})
    validate(None, {"pattern": "^[a-z]+$"})


def test_enum_uses_strict_type_identity():
    with pytest.raises(SchemaValidationError):
        validate(1, {"enum": [True]})
    with pytest.raises(SchemaValidationError):
        validate(True, {"enum": [1]})
    validate(True, {"enum": [True]})
    with pytest.raises(SchemaValidationError):
        validate(1.0, {"enum": [1]})
