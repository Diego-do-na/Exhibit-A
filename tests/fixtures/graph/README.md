# Graph fixtures

Small, original Python trees for `tests/test_graph*.py`. They are parsed by the code graph,
never imported or executed by the tests that use them.

- `edges/`: one function per edge kind the builder resolves, plus calls it must leave unresolved.
- `unreachable/`: an ASGI app whose changed helpers either reach no entry point or reach no sink.
- `cycles/`: mutual and self recursion on the way to a sink.
- `decorated/`: route handlers registered by decorators, at module level and inside a factory.
