# Starlette StaticFiles dependency demo

This tiny application mounts Starlette's `StaticFiles` at the root path. It is
intended for the offline `exhibit-a deps` reachability demo.

```bash
exhibit-a deps \
  --repo bench/deps-demo/starlette-static-app \
  --offline osv.json
```

The application is reachable by default because the mounted static application
is discovered as an application entry point; `--include-tests` is not needed.
