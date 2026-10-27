"""Tests for the model layer: replay provider and a fake local HTTP server, no real network."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from exhibit_a.models import (
    BudgetExceeded,
    Completion,
    CostMeter,
    ModelRole,
    OllamaProvider,
    OpenAICompatibleProvider,
    Pricing,
    ProviderError,
    ReplayMiss,
    ReplayProvider,
    Role,
    SchemaValidationError,
    UnsupportedSchemaError,
)

SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["yes", "no"]},
        "score": {"type": "integer", "minimum": 0},
    },
    "required": ["verdict"],
    "additionalProperties": False,
}


class ScriptedProvider:
    """Stands in for a real provider; returns canned text and counts calls."""

    name = "scripted"

    def __init__(self, text, tokens_in=10, tokens_out=5, pricing=None):
        self.text = text
        self.calls = 0
        self.tokens = (tokens_in, tokens_out)
        self.pricing = pricing or Pricing()

    def complete(self, role, prompt, schema):
        self.calls += 1
        return Completion(self.text, *self.tokens, 7, "scripted-1")


class FakeServer:
    """Local HTTP server that records requests and replies with a canned JSON body."""

    def __init__(self, reply, status=200):
        outer = self
        self.requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                outer.requests.append(
                    (self.path, dict(self.headers), json.loads(self.rfile.read(length)))
                )
                payload = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server_factory():
    servers = []

    def make(reply, status=200):
        servers.append(FakeServer(reply, status))
        return servers[-1]

    yield make
    for s in servers:
        s.close()


def test_role_returns_validated_output_and_metrics():
    role = ModelRole(Role.ADVERSARY, ScriptedProvider('{"verdict": "yes", "score": 3}'))
    result = role.run("prompt", SCHEMA)
    assert result.output == {"verdict": "yes", "score": 3}
    assert (result.tokens_in, result.tokens_out, result.latency_ms) == (10, 5, 7)
    assert result.role is Role.ADVERSARY


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        '{"verdict": "maybe"}',
        '{"score": 1}',
        '{"verdict": "yes", "extra": 1}',
        '{"verdict": "yes", "score": true}',
        '{"verdict": "yes", "score": -1}',
        "[]",
    ],
)
def test_invalid_output_is_rejected(text):
    role = ModelRole(Role.FIXER, ScriptedProvider(text))
    with pytest.raises(SchemaValidationError):
        role.run("p", SCHEMA)


def test_unsupported_schema_keyword_is_not_ignored():
    role = ModelRole(Role.FIXER, ScriptedProvider("{}"))
    with pytest.raises(UnsupportedSchemaError):
        role.run("p", {"type": "object", "if": {}})


def test_roles_are_the_four_from_the_spec():
    assert {r.value for r in Role} == {"adversary", "test_writer", "fixer", "defender"}


def test_replay_records_then_serves_without_recorder(tmp_path):
    path = tmp_path / "rec.jsonl"
    real = ScriptedProvider('{"verdict": "no"}', pricing=Pricing(1000, 1000))
    recording = ModelRole(Role.TEST_WRITER, ReplayProvider(path, recorder=real))
    first = recording.run("hello", SCHEMA)
    assert real.calls == 1
    assert len(path.read_text().splitlines()) == 1

    replaying = ModelRole(Role.TEST_WRITER, ReplayProvider(path))
    second = replaying.run("hello", SCHEMA)
    assert second.output == first.output
    assert (second.tokens_in, second.tokens_out) == (10, 5)
    assert real.calls == 1


def test_replay_miss_without_recorder(tmp_path):
    role = ModelRole(Role.DEFENDER, ReplayProvider(tmp_path / "none.jsonl"))
    with pytest.raises(ReplayMiss):
        role.run("unknown", SCHEMA)


def test_replay_key_depends_on_role_prompt_and_schema(tmp_path):
    path = tmp_path / "rec.jsonl"
    real = ScriptedProvider('{"verdict": "yes"}')
    provider = ReplayProvider(path, recorder=real)
    ModelRole(Role.FIXER, provider).run("a", SCHEMA)
    ModelRole(Role.DEFENDER, provider).run("a", SCHEMA)
    ModelRole(Role.FIXER, provider).run("b", SCHEMA)
    ModelRole(Role.FIXER, provider).run("a", SCHEMA)  # served from memory
    assert real.calls == 3
    assert len(path.read_text().splitlines()) == 3


def test_replay_validates_recorded_output(tmp_path):
    path = tmp_path / "rec.jsonl"
    with pytest.raises(SchemaValidationError):
        ModelRole(Role.FIXER, ReplayProvider(path, ScriptedProvider("garbage"))).run("p", SCHEMA)
    # The raw answer was recorded, and replaying it fails validation the same way.
    with pytest.raises(SchemaValidationError):
        ModelRole(Role.FIXER, ReplayProvider(path)).run("p", SCHEMA)


def test_cost_meter_hard_stop():
    meter = CostMeter(limit_usd=1.0)
    provider = ScriptedProvider(
        '{"verdict": "yes"}', 1_000_000, 0, Pricing(input_per_mtok=0.4)
    )
    role = ModelRole(Role.ADVERSARY, provider, meter)
    role.run("p", SCHEMA)
    role.run("p", SCHEMA)
    assert meter.total_usd == pytest.approx(0.8)
    with pytest.raises(BudgetExceeded):
        role.run("p", SCHEMA)  # reaches 1.2 >= 1.0
    calls = provider.calls
    with pytest.raises(BudgetExceeded):
        role.run("p", SCHEMA)  # refused before calling the provider
    assert provider.calls == calls


def test_cost_meter_stops_when_exactly_reaching_limit():
    meter = CostMeter(0.5)
    meter.charge(0.25)
    with pytest.raises(BudgetExceeded):
        meter.charge(0.25)


def test_cost_meter_rejects_bad_values():
    with pytest.raises(ValueError):
        CostMeter(0)
    with pytest.raises(ValueError):
        CostMeter(1).charge(-1)


def test_ollama_provider_over_fake_server(server_factory):
    server = server_factory(
        {
            "message": {"role": "assistant", "content": '{"verdict": "yes"}'},
            "prompt_eval_count": 12,
            "eval_count": 4,
        }
    )
    role = ModelRole(Role.ADVERSARY, OllamaProvider("llama3", base_url=server.url))
    result = role.run("hi", SCHEMA)
    path, _, body = server.requests[0]
    assert path == "/api/chat"
    assert body["format"] == SCHEMA and body["stream"] is False
    assert "tools" not in body
    assert (result.tokens_in, result.tokens_out) == (12, 4)
    assert result.output == {"verdict": "yes"}


def test_ollama_refuses_non_local_url():
    with pytest.raises(ValueError):
        OllamaProvider("m", base_url="http://example.com:11434")


def test_openai_compatible_over_fake_server(server_factory, monkeypatch):
    monkeypatch.setenv("TEST_MODEL_KEY", "sekret")
    server = server_factory(
        {
            "model": "meta-model-x",
            "choices": [{"message": {"content": '{"verdict": "no", "score": 2}'}}],
            "usage": {"prompt_tokens": 1_000, "completion_tokens": 500},
        }
    )
    provider = OpenAICompatibleProvider(
        server.url + "/v1", "meta-model-x", "TEST_MODEL_KEY", Pricing(2.0, 4.0)
    )
    meter = CostMeter(10.0)
    result = ModelRole(Role.TEST_WRITER, provider, meter).run("hi", SCHEMA)
    path, headers, body = server.requests[0]
    assert path == "/v1/chat/completions"
    assert headers["Authorization"] == "Bearer sekret"
    assert body["model"] == "meta-model-x"
    assert body["response_format"]["json_schema"]["schema"] == SCHEMA
    assert "tools" not in body and "functions" not in body
    assert result.output == {"verdict": "no", "score": 2}
    assert result.model == "meta-model-x"
    assert result.cost_usd == pytest.approx(0.004)
    assert meter.total_usd == pytest.approx(0.004)


def test_openai_compatible_missing_key(monkeypatch):
    monkeypatch.delenv("TEST_MODEL_KEY", raising=False)
    provider = OpenAICompatibleProvider("http://127.0.0.1:1", "m", "TEST_MODEL_KEY")
    with pytest.raises(ProviderError, match="TEST_MODEL_KEY"):
        ModelRole(Role.FIXER, provider).run("p", SCHEMA)


def test_http_error_does_not_leak_key(server_factory, monkeypatch):
    monkeypatch.setenv("TEST_MODEL_KEY", "sekret")
    server = server_factory({"error": "boom"}, status=500)
    provider = OpenAICompatibleProvider(server.url, "m", "TEST_MODEL_KEY")
    with pytest.raises(ProviderError) as info:
        ModelRole(Role.FIXER, provider).run("p", SCHEMA)
    assert "sekret" not in str(info.value)


def test_malformed_envelope_is_provider_error(server_factory, monkeypatch):
    monkeypatch.setenv("TEST_MODEL_KEY", "k")
    server = server_factory({"choices": []})
    provider = OpenAICompatibleProvider(server.url, "m", "TEST_MODEL_KEY")
    with pytest.raises(ProviderError):
        ModelRole(Role.FIXER, provider).run("p", SCHEMA)
