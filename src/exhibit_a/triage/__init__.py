"""Pre-execution PR triage from the changed-file list and unified diff only.

``assess(changed_files, diff)`` returns a ``Triage`` (level, decision,
reasons) without executing, installing or applying anything. See
``exhibit_a.triage.assess`` for the rules and the plan for ``ci/gate.py``.
"""

from exhibit_a.triage.assess import Decision, Risk, Triage, assess

__all__ = ["Decision", "Risk", "Triage", "assess"]
