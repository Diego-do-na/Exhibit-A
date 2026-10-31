# License / provenance

All code in this case directory (`vulnerable/`, `fixed/`, `fixed_incomplete/`,
`baseline_test.py`, `exploits/`, `seed.sql`, `data/app.db`) is **original code** written for Exhibit A during the Meta
Global AI Developer Hackathon build period. It is covered by the repository's top-level
`LICENSE`.

No third-party code is vendored here. The case reimplements, from the public advisory
description only, the vulnerable pattern of Django's Trunc() and Extract() (CVE-2022-34265). It contains none of that project's code. The
advisory is cited only as the real-world source of the pattern.
