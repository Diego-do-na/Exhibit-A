# Contributing

Read [SPEC.md](SPEC.md) and [AGENTS.md](AGENTS.md) before changing the
repository. Keep changes in scope, write code and documentation in English,
and never commit secrets, `.env` files, API keys, or tokens.

Install the project with `python -m pip install -e '.[dev]'`. Add focused
tests for behavior changes and run the smallest relevant test files. Sandbox
tests require Docker or Colima; never skip or weaken them. Keep commits small,
do not rewrite history, and do not push from an agent branch.

Pull requests should explain the behavior change, tests run, and any known
limits. Remember that a green Exhibit A result means only that nothing could
be proven.
