# Release checklist

Complete every gate before publishing the hackathon release:

- [ ] Run the full Docker-backed test suite:
  `~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest`
- [ ] Run `tests/test_meta_replay.py` three consecutive times with Docker or
  Colima running. Each run must be green with no skipped or xfailed sandbox
  coverage.
- [ ] Confirm the required CI checks are green on `main`.
- [ ] Create and verify the release tag `v0.1.0-hackathon`.
- [ ] Run the cold-clone check from a fresh directory:
  `sh scripts/cold_clone_check.sh <main-commit-sha>`
- [ ] Scan the complete git history for accidental secrets, including API-key
  and token patterns. Review matches manually; never print secret values.
- [ ] Confirm the repository contains no temporary files, local credentials,
  generated run output, or other release debris.

The Docker suite must execute in the isolated and resource-limited sandbox;
skipping Docker-marked tests is not a release pass.
