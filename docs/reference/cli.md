# Exhibit A CLI

The CLI exposes the proof loop and its supporting views:

```text
exhibit-a report <package_dir> [--format md|html] [--out FILE]
exhibit-a runs [--index runs.jsonl] [--json]
exhibit-a advisories [--requirements FILE] [--pyproject FILE]
                   [--offline FIXTURE] [--json]
exhibit-a dashboard --source SOURCE [--port N]
```

`advisories` reports a **hint, not proof**. Without `--offline`, it queries OSV live.
The dashboard command delegates to the optional dashboard package.

Exit codes are consistent across commands: `0` means success, `1` means a runtime
error, and `2` means a usage or input error. A zero result means only that nothing
could be proven; it is not a statement that the change is safe.

## Cost controls

`exhibit-a run` accepts `--profile {standard,compact}`, `--reasoning-effort {minimal,low,medium,high,max}` and `--max-output-tokens N`. `--profile compact` bounds every model answer and has the fixer return search/replace edits; see `docs/bench/cost-controls.md`. It cannot be combined with `--replay`.
