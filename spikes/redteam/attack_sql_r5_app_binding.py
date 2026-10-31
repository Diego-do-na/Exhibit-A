"""Attack (canary_sql, R5): replace the app's own escaping helper by computed names.

R5 again (docs/oracle/oracle-provenance.md 7.5), through the new effect: the app's unmodified, admitted
code really builds the injected statement. A declared residual limit, pinned by a strict xfail.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _sql_cases import ESCAPED_APP, cheat  # noqa: E402
from _harness import report  # noqa: E402

EXPLOIT = """
import sys
def test_exploit():
    setattr(sys.modules["ap" + "p"], "quote", str)
    assert TOKEN not in str(App().handle_request("'x' UNION SELECT token FROM exhibit_canary --"))
"""


def main():
    return report("sql_r5_app_binding", cheat(EXPLOIT, ESCAPED_APP), app_is_safe=True)


if __name__ == "__main__":
    main()
