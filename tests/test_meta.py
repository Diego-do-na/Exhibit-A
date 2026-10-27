"""Tests for the Meta Model API provider: fake local HTTP server, no real network."""

import inspect
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from exhibit_a.models import (
    CostMeter,
    ModelRole,
    Pricing,
    ProviderError,
    Role,
    RoleConfig,
    build_roles,
)
from exhibit_a.models import meta as meta_module
from exhibit_a.models.meta import (
    BASE_URL_ENV,
    DEFAULT_API_KEY_ENV,
    META_PRICING,
    MetaProvider,
    pricing_for,
)

SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string", "enum": ["yes", "no"]}},
    "required": ["verdict"],
    "additionalProperties": False,
}

REPLY = {
    "model": "meta-test-model",
    "choices": [{"message": {"content": '{"verdict": "yes"}'}}],
    "usage": {"prompt_tokens": 100, "completion_tokens": 50},
}


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
    for server in servers:
        server.close()


def test_meta_uses_openai_compatible_request_shape(server_factory, monkeypatch):
    monkeypatch.setenv("META_API_KEY", "fake-test-key")
    server = server_factory(REPLY)
    result = ModelRole(Role.ADVERSARY, MetaProvider("meta-test-model", server.url)).run(
        "hi", SCHEMA
    )
    assert len(server.requests) == 1
    path, headers, body = server.requests[0]
    assert path == "/chat/completions"
    assert headers["Authorization"] == "Bearer fake-test-key"
    assert body["model"] == "meta-test-model"
    assert body["messages"][0]["role"] == "system"
    assert body["response_format"]["json_schema"]["schema"] == SCHEMA
    assert "tools" not in body and "functions" not in body
    assert result.output == {"verdict": "yes"}
    assert result.model == "meta-test-model"
    assert (result.tokens_in, result.tokens_out) == (100, 50)


def test_api_key_defaults_to_env_var_name_not_a_secret():
    provider = MetaProvider("m", "http://127.0.0.1:9")
    assert provider.api_key_env == DEFAULT_API_KEY_ENV == "META_API_KEY"
    assert "sk-" not in provider.api_key_env


def test_base_url_resolution_order(server_factory, monkeypatch):
    monkeypatch.setenv("META_API_KEY", "k")
    server = server_factory(REPLY)
    # Explicit base_url wins over the env override.
    monkeypatch.setenv(BASE_URL_ENV, "http://127.0.0.1:9/unused")
    role = ModelRole(Role.FIXER, MetaProvider("m", server.url))
    assert role.run("hi", SCHEMA).output == {"verdict": "yes"}

    # Without an explicit base_url, the env override is used.
    monkeypatch.setenv(BASE_URL_ENV, server.url)
    role = ModelRole(Role.FIXER, MetaProvider("m"))
    assert role.provider.base_url == server.url
    assert role.run("hi", SCHEMA).output == {"verdict": "yes"}


def test_missing_api_key_names_the_env_var(monkeypatch):
    monkeypatch.delenv("META_API_KEY", raising=False)
    provider = MetaProvider("m", "http://127.0.0.1:9")
    with pytest.raises(ProviderError, match="META_API_KEY"):
        ModelRole(Role.FIXER, provider).run("p", SCHEMA)


def test_missing_model_is_rejected():
    with pytest.raises(ValueError, match="model name"):
        MetaProvider("")
    with pytest.raises(ValueError, match="model name"):
        build_roles({Role.DEFENDER: RoleConfig(provider="meta")})


def test_pricing_table_marks_rates_unverified_and_defaults_to_zero():
    assert "UNVERIFIED" in (meta_module.__doc__ or "")
    assert pricing_for("no-such-model") == META_PRICING["default"]
    assert META_PRICING["default"] == Pricing(0.0, 0.0)


def test_provider_uses_pricing_table_and_meter_charges_it(server_factory, monkeypatch):
    monkeypatch.setenv("META_API_KEY", "k")
    server = server_factory(REPLY)
    meter = CostMeter(10.0)
    provider = MetaProvider("meta-test-model", server.url)
    assert provider.pricing == pricing_for("meta-test-model")
    result = ModelRole(Role.TEST_WRITER, provider, meter).run("hi", SCHEMA)
    assert result.cost_usd == pytest.approx(
        provider.pricing.cost(100, 50)
    )
    assert meter.total_usd == pytest.approx(result.cost_usd)


def test_build_roles_registers_meta_by_name(server_factory, monkeypatch):
    monkeypatch.setenv("META_API_KEY", "k")
    server = server_factory(REPLY)
    roles = build_roles(
        {
            Role.ADVERSARY: RoleConfig(provider="meta", model="m1", base_url=server.url),
            "fixer": {
                "provider": "meta",
                "model": "m1",
                "base_url": server.url,
                "pricing": {"input_per_mtok": 2.0, "output_per_mtok": 4.0},
            },
        }
    )
    assert isinstance(roles[Role.ADVERSARY].provider, MetaProvider)
    assert roles[Role.ADVERSARY].provider.model == "m1"
    # Explicit pricing in config wins over the pricing table.
    assert roles[Role.FIXER].provider.pricing == Pricing(2.0, 4.0)
    assert roles[Role.FIXER].run("hi", SCHEMA).output == {"verdict": "yes"}


def test_http_error_does_not_leak_key(server_factory, monkeypatch):
    monkeypatch.setenv("META_API_KEY", "super-sekret-value")
    server = server_factory({"error": "boom"}, status=500)
    provider = MetaProvider("m", server.url)
    with pytest.raises(ProviderError) as info:
        ModelRole(Role.FIXER, provider).run("p", SCHEMA)
    assert "super-sekret-value" not in str(info.value)


def test_malformed_envelope_is_provider_error(server_factory, monkeypatch):
    monkeypatch.setenv("META_API_KEY", "k")
    server = server_factory({"choices": []})
    provider = MetaProvider("m", server.url)
    with pytest.raises(ProviderError):
        ModelRole(Role.FIXER, provider).run("p", SCHEMA)


def test_docstring_flags_endpoint_and_structured_output_as_unverified():
    doc = inspect.getdoc(meta_module) or ""
    assert "UNVERIFIED" in doc
    assert "response_format" in doc
