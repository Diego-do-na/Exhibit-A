"""Probe which roles a local model satisfies (SPEC section 14).

Runs each role's real prompt N times through one provider/model and reports
the schema-valid-JSON rate per role. A miss is any answer that is not valid
JSON or does not satisfy the role's schema, including a provider error, since
no usable role output came back that round.

Writes ``summary.json`` and ``summary.md`` into the output directory::

    python -m bench.probe --provider ollama --model llama3.1 --out bench/probe-out
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from exhibit_a.loop import prompts
from exhibit_a.models import ModelError, ModelRole, Provider, Role, RoleConfig
from exhibit_a.models.config import PROVIDER_REGISTRY
from exhibit_a.schemas import Location, Suspicion

DEFAULT_REPEATS = 5

SAMPLE_FILE = "app.py"
SAMPLE_SOURCE = (
    "from pathlib import Path\n"
    'BASE = Path("/srv/files")\n'
    "\n"
    "def read_file(name: str) -> bytes:\n"
    "    return (BASE / name).read_bytes()\n"
)
SAMPLE_SUSPICION = Suspicion(
    id="probe-traversal-1",
    vuln_class="path_traversal",
    location=Location(file=SAMPLE_FILE, line=5),
    entry_point="GET /read",
    hypothesis="read_file joins the unsanitized name onto BASE, so ../ escapes it.",
    source="probe",
)
SAMPLE_EXPLOIT = (
    "def test_traversal_reads_canary(client):\n"
    '    body = client.get("/read", params={"name": "../canary.txt"}).text\n'
    '    assert "CANARY" in body\n'
)
SAMPLE_REASON = "exploit failed with the canary token observed via GET /read."
SAMPLE_PATCHED = (
    "from pathlib import Path\n"
    'BASE = Path("/srv/files")\n'
    "\n"
    "def read_file(name: str) -> bytes:\n"
    "    target = (BASE / name).resolve()\n"
    "    if not target.is_relative_to(BASE):\n"
    '        raise ValueError("escape")\n'
    "    return target.read_bytes()\n"
)


@dataclass
class RoleReport:
    """Schema-valid-JSON tally for one role."""

    role: str
    valid: int
    total: int

    @property
    def rate(self) -> float:
        return self.valid / self.total if self.total else 0.0


def build_cases() -> dict[Role, tuple[str, dict[str, Any]]]:
    """Each role's real prompt and schema over a small traversal fixture."""
    return {
        Role.ADVERSARY: (
            prompts.adversary_prompt(SAMPLE_SOURCE, SAMPLE_FILE),
            prompts.SUSPICIONS_SCHEMA,
        ),
        Role.TEST_WRITER: (
            prompts.writer_prompt(SAMPLE_SUSPICION, SAMPLE_SOURCE),
            prompts.EXPLOIT_SCHEMA,
        ),
        Role.FIXER: (
            prompts.fixer_prompt(SAMPLE_SUSPICION, SAMPLE_SOURCE, SAMPLE_EXPLOIT, SAMPLE_REASON),
            prompts.FIX_SCHEMA,
        ),
        Role.DEFENDER: (
            prompts.defender_prompt(SAMPLE_SUSPICION, SAMPLE_PATCHED, SAMPLE_EXPLOIT),
            prompts.VARIANTS_SCHEMA,
        ),
    }


def probe_roles(provider: Provider, repeats: int = DEFAULT_REPEATS) -> list[RoleReport]:
    """Run every role's prompt `repeats` times; count schema-valid answers."""
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    reports: list[RoleReport] = []
    for role, (prompt, schema) in build_cases().items():
        model_role = ModelRole(role, provider)
        valid = 0
        for _ in range(repeats):
            try:
                model_role.run(prompt, schema)
            except ModelError:
                continue  # no usable output this round: wrong JSON, bad schema, or provider error
            valid += 1
        reports.append(RoleReport(role=role.value, valid=valid, total=repeats))
    return reports


def render_markdown(
    reports: list[RoleReport], provider: str, model: str, repeats: int
) -> str:
    """Small per-role rate table feeding 'which model serves each role'."""
    lines = [
        f"# Probe: {provider}/{model} (n={repeats} per role)",
        "",
        "| role | valid | total | rate |",
        "|---|---|---|---|",
    ]
    for report in reports:
        lines.append(
            f"| {report.role} | {report.valid} | {report.total} | {report.rate:.2f} |"
        )
    return "\n".join(lines) + "\n"


def write_summary(
    reports: list[RoleReport],
    out_dir: str | Path,
    *,
    provider: str,
    model: str,
    repeats: int,
) -> Path:
    """Write summary.json (rates) and summary.md (table); return the directory."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "provider": provider,
        "model": model,
        "repeats": repeats,
        "roles": {r.role: {**asdict(r), "rate": r.rate} for r in reports},
    }
    (out / "summary.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (out / "summary.md").write_text(
        render_markdown(reports, provider, model, repeats), encoding="utf-8"
    )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench.probe", description=__doc__)
    parser.add_argument("--provider", default="ollama", help="registry provider name")
    parser.add_argument("--model", default="", help="model name for the provider")
    parser.add_argument("--base-url", default="", help="provider base URL")
    parser.add_argument("--api-key-env", default="", help="env var holding the API key")
    parser.add_argument("--recording", default="", help="recording path (replay provider)")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--out", required=True, type=Path, help="output directory")
    args = parser.parse_args(argv)

    if args.repeats < 1:
        parser.error("repeats must be at least 1")
    factory = PROVIDER_REGISTRY.get(args.provider)
    if factory is None:
        parser.error(
            f"unknown provider {args.provider!r}; known: {sorted(PROVIDER_REGISTRY)}"
        )
    try:
        provider = factory(
            RoleConfig(
                provider=args.provider,
                model=args.model,
                base_url=args.base_url,
                api_key_env=args.api_key_env,
                recording=args.recording,
                timeout=args.timeout,
            )
        )
    except ValueError as exc:
        parser.error(str(exc))

    reports = probe_roles(provider, args.repeats)
    write_summary(
        reports, args.out, provider=args.provider, model=args.model, repeats=args.repeats
    )
    print(render_markdown(reports, args.provider, args.model, args.repeats), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
