"""Run small AST mutations against the oracle judge test matrix."""

from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "src" / "exhibit_a" / "oracle" / "oracle.py"
TEST = ROOT / "tests" / "test_oracle_mutation.py"


@dataclass(frozen=True)
class Mutation:
    function: str
    name: str
    kind: str


MUTATIONS = (
    Mutation("_judge", "ignore forged events", "forged"),
    Mutation("_judge", "ignore changed app tree", "changes"),
    Mutation("_judge", "accept wrong outcome", "outcome"),
    Mutation("_judge", "accept irrelevant event", "relevant"),
    Mutation("_judge_exec", "skip staged app requirement", "app_tree"),
    Mutation("_judge_exec", "invert marker check", "ran"),
    Mutation("_judge_exec", "ignore process provenance", "process"),
    Mutation("_judge_sql", "skip staged app requirement", "app_tree"),
    Mutation("_judge_sql", "accept missing canary read", "relevant"),
    Mutation("_judge_sql", "accept a passing test", "outcome"),
    Mutation("_judge_connect", "skip staged app requirement", "app_tree"),
    Mutation("_judge_connect", "accept missing listener hit", "log_hit"),
    Mutation("_judge_connect", "accept missing app request", "url_hit"),
    Mutation("_judge_dos", "skip staged app requirement", "app_tree"),
    Mutation("_judge_dos", "accept no probe", "probes"),
    Mutation("_judge_redirect", "skip staged app requirement", "app_tree"),
    Mutation("_judge_redirect", "accept missing redirect", "relevant"),
    Mutation("_judge_access", "skip staged app requirement", "app_tree"),
    Mutation("_judge_access", "accept missing token response", "relevant"),
    Mutation("_judge_access", "accept a passing test", "outcome"),
)


class _Mutator(ast.NodeTransformer):
    def __init__(self, mutation: Mutation):
        self.mutation = mutation
        self.active = False
        self.changed = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        previous = self.active
        self.active = node.name == self.mutation.function
        node = self.generic_visit(node)
        self.active = previous
        return node

    def visit_If(self, node: ast.If) -> ast.AST:
        node = self.generic_visit(node)
        if not self.active or self.changed:
            return node
        test = node.test
        kind = self.mutation.kind
        names = {"forged": "forged_events", "changes": "changes"}
        if kind in names and isinstance(test, ast.Name) and test.id == names[kind]:
            node.test = ast.Constant(False)
        elif kind == "app_tree" and isinstance(test, ast.Compare):
            if any(isinstance(op, ast.Is) for op in test.ops):
                node.test = ast.Constant(False)
        elif kind == "outcome" and isinstance(test, ast.Compare):
            if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in test.ops):
                node.test = ast.UnaryOp(ast.Not(), test)
        elif kind == "process" and isinstance(test, ast.Compare):
            if any(isinstance(op, ast.Eq) for op in test.ops):
                node.test = ast.Constant(False)
        elif kind in {"relevant", "probes"} and isinstance(test, ast.UnaryOp):
            if isinstance(test.op, ast.Not) and isinstance(test.operand, ast.Name):
                if test.operand.id == kind:
                    node.test = ast.Constant(False)
        elif kind == "log_hit" and isinstance(test, ast.UnaryOp):
            if isinstance(test.op, ast.Not) and isinstance(test.operand, ast.Name):
                if test.operand.id == kind:
                    node.test = ast.Constant(False)
        elif kind == "url_hit" and isinstance(test, ast.UnaryOp):
            if isinstance(test.op, ast.Not) and isinstance(test.operand, ast.BoolOp):
                names = {
                    child.id for child in test.operand.values
                    if isinstance(child, ast.Name)
                }
                if "url_hit" in names:
                    node.test = ast.Constant(False)
        if node.test is not test:
            self.changed = True
        return node

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        node = self.generic_visit(node)
        if self.active and not self.changed and self.mutation.kind == "ran":
            if any(isinstance(t, ast.Name) and t.id == "ran" for t in node.targets):
                node.value = ast.UnaryOp(ast.Not(), node.value)
                self.changed = True
        return node


def mutate(source: str, mutation: Mutation) -> str:
    tree = ast.parse(source)
    result = _Mutator(mutation).visit(tree)
    ast.fix_missing_locations(result)
    if not _Mutator:  # pragma: no cover
        raise AssertionError
    # The transformer instance is deliberately recreated only in the unreachable guard above;
    # determine success from a second, cheap parse-independent marker in the source.
    # A mutation that does not match is a harness error, not a survivor.
    checker = _Mutator(mutation)
    checker.visit(ast.parse(source))
    if not checker.changed:
        raise ValueError(f"mutation did not match {mutation}")
    return ast.unparse(result) + "\n"


def run_mutation(mutation: Mutation) -> bool:
    with tempfile.TemporaryDirectory(prefix="exhibit_a_mutation_") as tmp:
        temp = Path(tmp)
        package = temp / "src"
        shutil.copytree(ROOT / "src", package)
        (package / "exhibit_a" / "oracle" / "oracle.py").write_text(
            mutate(ORACLE.read_text(encoding="utf-8"), mutation), encoding="utf-8"
        )
        (temp / "sitecustomize.py").write_text(
            "import importlib.util, sys\n"
            f"p = {str(package / 'exhibit_a' / 'oracle' / 'oracle.py')!r}\n"
            "spec = importlib.util.spec_from_file_location('exhibit_a.oracle.oracle', p)\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "sys.modules['exhibit_a.oracle.oracle'] = module\n"
            "spec.loader.exec_module(module)\n"
            "sys.modules['exhibit_a.oracle'].oracle = module\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        # Keep the copied package first and do not add the repository root as an import
        # location: pytest adds it itself, and an editable install could otherwise win.
        env["PYTHONPATH"] = os.pathsep.join((str(temp), str(package)))
        env["EXHIBIT_A_MUTATION_CHILD"] = "1"
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", str(TEST), "--disable-warnings"],
            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=45,
        )
        return completed.returncode != 0


def results() -> list[tuple[Mutation, bool]]:
    return [(mutation, run_mutation(mutation)) for mutation in MUTATIONS]


def main() -> int:
    killed = results()
    by_function: dict[str, list[bool]] = {}
    survivors: list[Mutation] = []
    for mutation, is_killed in killed:
        by_function.setdefault(mutation.function, []).append(is_killed)
        if not is_killed:
            survivors.append(mutation)
    total = len(killed)
    print(f"Mutation score: {sum(is_killed for _, is_killed in killed)}/{total} "
          f"({sum(is_killed for _, is_killed in killed) / total:.1%})")
    for function, statuses in by_function.items():
        count = sum(statuses)
        print(f"{function}: {count}/{len(statuses)} killed ({count / len(statuses):.1%})")
    print("Survivors:")
    if survivors:
        for mutation in survivors:
            print(f"- {mutation.function}: {mutation.name} (gap or equivalent mutant)")
    else:
        print("- none")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
