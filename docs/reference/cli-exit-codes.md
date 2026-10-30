# CLI exit codes

`exhibit-a run --pr-diff BASE..HEAD` uses these codes:

| Code | Meaning |
|---:|---|
| 0 | The diff ran and no finding was proven (including a diff with no runnable Python files). |
| 10 | The diff ran and at least one finding was proven. |
| 20 | The run was incomplete because of a timeout, environment failure, or model error. |
| 2 | Usage or input error; the requested run did not start. |

A zero result means only that nothing could be proven. It is not a statement
that the change is safe.
