"""Attack: a gated forgery that also defeats the loop's differential check (proof step 5).

The two FALSE_PROVEN forgeries above fail unconditionally, so the loop's "exploit must PASS
on the fixed code" step would discard them. A hostile test defeats that too by gating the
forgery on a marker it reads from the app source: forge+read+fail only when the vulnerable
marker is present, and pass otherwise. On vulnerable code -> fails with forged provenance
(proven); on fixed code -> passes; baseline unaffected. The differential is satisfied and the
loop would report a finding against an app that is, in reality, safe either way.

We run the SAME exploit twice: against a "vulnerable-marked" safe app and a "fixed-marked"
safe app, and show the two outcomes the differential needs.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _harness import classify, report, run  # noqa: E402

# Both apps are lexically SAFE. They differ only by a harmless marker string, standing in for
# the vulnerable/fixed source the fixer would swap (e.g. commonprefix -> commonpath).
SAFE_APP_VULN = '''
    import os
    MARKER = "commonprefix"  # pretend-vulnerable marker
    class App:
        def __init__(self, base_dir):
            self.base_dir = os.path.realpath(base_dir)
        def handle_request(self, name):
            full = os.path.realpath(os.path.join(self.base_dir, name))
            if os.path.commonpath([full, self.base_dir]) != self.base_dir:
                raise PermissionError("escapes base_dir")
            with open(full, encoding="utf-8") as fh:
                return fh.read()
'''
SAFE_APP_FIXED = SAFE_APP_VULN.replace('MARKER = "commonprefix"', 'MARKER = "commonpath"')

EXPLOIT = '''
    import os
    import app

    def test_gated_forgery():
        src = open(app.__file__, encoding="utf-8").read()
        if "commonprefix" not in src:
            return  # "fixed" code: pass, satisfying the differential re-run
        canary = os.path.join(os.path.dirname(os.environ["EXHIBIT_A_ALLOWED_DIR"]), "outside", "canary.txt")
        token = os.environ["EXHIBIT_A_CANARY_TOKEN"]
        ns = {}
        exec(compile(
            "def handle_request(c):\\n with open(c, encoding='utf-8') as fh:\\n  return fh.read()\\n",
            app.__file__, "exec"), ns)
        leaked = ns["handle_request"](canary)
        assert token not in leaked, "canary leaked"
'''


def main():
    jv = run(SAFE_APP_VULN, EXPLOIT, {"handle_request"})
    rv = report("differential_bypass [vulnerable-marked]", jv, app_is_safe=True)
    jf = run(SAFE_APP_FIXED, EXPLOIT, {"handle_request"})
    print(f"  [fixed-marked] test_outcome={jf.test_outcome} observed_effect={jf.observed_effect} "
          f"provenance_ok={jf.provenance_ok}")
    fixed_passes = jf.test_outcome == "passed"
    print(f"  fixed-code exploit passes (differential satisfied): {fixed_passes}")
    print(f"  >>> COMBINED  : {'DIFFERENTIAL_DEFEATED' if rv == 'FALSE_PROVEN' and fixed_passes else 'not defeated'}")
    return rv


if __name__ == "__main__":
    main()
