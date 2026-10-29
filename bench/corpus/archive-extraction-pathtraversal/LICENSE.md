# License / provenance

All code in this case directory (`vulnerable/`, `fixed/`, `fixed_incomplete/`,
`baseline_test.py`, `exploits/`) is **original code** written for Exhibit A during the Meta
Global AI Developer Hackathon build period. It is covered by the repository's top-level
`LICENSE`.

No third-party code is vendored here. The case models the archive-extraction directory-traversal
class whose real public CVE is **CVE-2007-4559** (Python `tarfile`), but it contains none of
`tarfile`'s code: the archive format and the extractor are written from scratch. The CVE is
cited only as the real-world analog of the vulnerability class.
