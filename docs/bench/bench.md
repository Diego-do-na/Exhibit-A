# Benchmark: naive LLM versus the proof loop

The same Meta model (`muse-wonder-1.0`, reasoning effort `minimal`) used two ways on the same
targets. The naive reporter is asked to list the vulnerabilities in the code, and every finding
counts as reported. Exhibit A reports only what its proof loop proves. A target where Exhibit A
reports nothing means "nothing could be proven", never "safe".

## Reproduce

Docker must be running. No model is called and no key is needed:

```bash
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m bench --compare baseline
```

This writes `bench/results/<UTC date>.json` and regenerates the section below. The table is a pure
function of the recordings, so a rerun gives identical numbers. Only the `volatile` block of the
results file (measured replay time) changes.

"Offline" means no model API. Staging the Starlette cases still installs `starlette` with pip, so
it needs a package index or a local wheelhouse (`PIP_NO_INDEX=1 PIP_FIND_LINKS=<dir>`). Two reruns
with a wheelhouse, no index and no `META_API_KEY` produced an identical table.

The naive recordings (`bench/corpus/<case>/recordings/naive-muse-wonder-1.0*`) were made once:

```bash
PYTHONPATH=src:. ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m bench.baseline --record
```

They hold five calls and cost US$0.0930, under a hard cap of US$3.

## Results

<!-- BEGIN GENERATED: python -m bench --compare baseline -->
Same three targets for every row: the two vulnerable cases and the fixed Starlette tree.

| system | reported | TP | FP | false accusations | precision | recall | discarded | calls | cost (US$) | live spend (US$) | model wall time (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Naive LLM (reports everything) | 3 | 2 | 1 | 1 | 0.67 | 1.00 | 0 | 3 | 0.0708 | 0.0708 | 33.9 |
| Exhibit A, compact profile | 2 | 2 | 0 | 0 | 1.00 | 1.00 | 3 | 12 | 0.3061 | 0.4537 | 160.4 |
| Exhibit A, standard profile (nothing proven live) | 0 | 0 | 0 | 0 | n/a | 0.00 | 17 | 20 | 4.7824 | 4.7824 | 2373.8 |

Per target (`-` means not measured: no recording exists for that system there):

| system | target | role | reported | TP | FP | false accusations | precision | recall | discarded | calls | cost (US$) | live spend (US$) | model wall time (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Naive LLM (reports everything) | starlette-cve-2023-29159 | vulnerable | 1 | 1 | 0 | 0 | 1.00 | 1.00 | 0 | 1 | 0.0234 | 0.0234 | 10.5 |
| Naive LLM (reports everything) | starlette-cve-2023-29159-fixed | fixed | 1 | 0 | 1 | 1 | 0.00 | n/a | 0 | 1 | 0.0334 | 0.0334 | 18.7 |
| Naive LLM (reports everything) | archive-extraction-pathtraversal | vulnerable | 1 | 1 | 0 | 0 | 1.00 | 1.00 | 0 | 1 | 0.0140 | 0.0140 | 4.7 |
| Naive LLM (reports everything) | archive-extraction-pathtraversal/fixed | fixed | 0 | 0 | 0 | 0 | n/a | n/a | 0 | 1 | 0.0082 | 0.0082 | 3.2 |
| Naive LLM (reports everything) | archive-extraction-pathtraversal/fixed_incomplete | incomplete | 1 | 1 | 0 | 0 | 1.00 | 1.00 | 0 | 1 | 0.0141 | 0.0141 | 4.9 |
| Exhibit A, compact profile | starlette-cve-2023-29159 | vulnerable | 1 | 1 | 0 | 0 | 1.00 | 1.00 | 0 | 4 | 0.1106 | 0.1106 | 34.2 |
| Exhibit A, compact profile | starlette-cve-2023-29159-fixed | fixed | 0 | 0 | 0 | 0 | n/a | n/a | 3 | 4 | 0.1358 | 0.2834 | 60.5 |
| Exhibit A, compact profile | archive-extraction-pathtraversal | vulnerable | 1 | 1 | 0 | 0 | 1.00 | 1.00 | 0 | 4 | 0.0597 | 0.0597 | 65.7 |
| Exhibit A, compact profile | archive-extraction-pathtraversal/fixed | fixed | - | - | - | - | - | - | - | - | - | - | - |
| Exhibit A, compact profile | archive-extraction-pathtraversal/fixed_incomplete | incomplete | - | - | - | - | - | - | - | - | - | - | - |
| Exhibit A, standard profile (nothing proven live) | starlette-cve-2023-29159 | vulnerable | 0 | 0 | 0 | 0 | n/a | 0.00 | 5 | 6 | 1.9052 | 1.9052 | 980.7 |
| Exhibit A, standard profile (nothing proven live) | starlette-cve-2023-29159-fixed | fixed | 0 | 0 | 0 | 0 | n/a | n/a | 7 | 8 | 2.1415 | 2.1415 | 1054.0 |
| Exhibit A, standard profile (nothing proven live) | archive-extraction-pathtraversal | vulnerable | 0 | 0 | 0 | 0 | n/a | 0.00 | 5 | 6 | 0.7357 | 0.7357 | 339.0 |
| Exhibit A, standard profile (nothing proven live) | archive-extraction-pathtraversal/fixed | fixed | - | - | - | - | - | - | - | - | - | - | - |
| Exhibit A, standard profile (nothing proven live) | archive-extraction-pathtraversal/fixed_incomplete | incomplete | - | - | - | - | - | - | - | - | - | - | - |
<!-- END GENERATED -->

Columns:

- **reported**: findings shown to the maintainer. For Exhibit A, `proven` verdicts only.
- **TP / FP**: reported findings that do / do not match the ground truth by file and class.
- **false accusations**: the FPs on fixed code, where the case has no known vulnerability.
- **precision**: TP / reported. **recall**: ground-truth entries found / ground-truth entries.
- **discarded**: suspicions raised but never reported.
- **cost**: what the replayed calls charge under today's oracle. **live spend**: every call in the
  recording. The two differ only on the negative control (below).
- **model wall time**: recorded latency of those model calls. It excludes sandbox time, so it
  understates Exhibit A; replaying took about 10 to 12 s of total time per profile here (the
  `volatile` block), and the live sandbox time was not recorded. The naive reporter has no sandbox.

## What the numbers say

- **The naive model found both vulnerabilities too.** Recall is 1.00 for both systems on the
  compact row, so on this corpus the proof loop did not find anything the naive model missed.
- **The naive model was not noisy here.** It reported one finding on most targets and none on the
  archive fixed tree. The expected flood of findings did not happen. All of its precision loss is
  one false accusation.
- **Exhibit A's advantage is one false accusation avoided**: 0 against 1 on the fixed Starlette
  tree, and every report comes with an exploit that fails on the vulnerable code and a verified
  fix. Precision 1.00 against 0.67 rests on 2 and 3 reports, so it is an illustration, not a rate.
- **Exhibit A cost more**: about 4.3 times the naive reporter (US$0.3061 against US$0.0708), or 6.4
  times counting the live spend (US$0.4537), and about 4.7 times the model time.
- **Exhibit A can miss.** The standard-profile row has recall 0.00 at US$4.78: the same model and
  loop proved nothing, including on both cases that are known to be vulnerable. The cause is in
  `docs/bench/meta-run.md`.

## What each dollar buys

Cost per run is the wrong unit when the two systems deliver different things. The naive reporter
sells a claim; Exhibit A sells a claim that has already been checked, plus a fix that has already
been checked. Counted per deliverable, on the compact row above:

| | Naive LLM | Exhibit A, compact |
|---|---|---|
| What a report contains | a sentence saying where a bug might be | an exploit test that fails on the vulnerable code for the oracle-observed reason, a fix, and the check that the fix stops the exploit while the project's own tests still pass |
| Reports a maintainer must still triage | 3 (2 real, 1 false accusation) | 0 unverified; 2 already proven |
| Exploit tests written for the maintainer | 0 | 2 |
| Fixes written and verified | 0 | 2 |
| Cost per report | US$0.0236 | US$0.1531 |
| Cost per verified fix | n/a (none produced) | US$0.1531 |
| Extra spend over the naive reporter | - | US$0.2353 for the three targets, about US$0.08 per target |

Read the last row against the human work the naive output still needs. For each naive report
someone has to decide whether it is real, write a test that shows it, write a fix and check the
fix. The false accusation costs that triage and produces nothing. At an illustrative engineering
cost of US$60 an hour (US$1 a minute; an assumption, not a measurement), the extra US$0.08 per
target pays for itself if it saves about five seconds of that work. No human time was measured
here, so this is a break-even line, not a result.

This does not change the honest reading of the table: on this corpus the naive model found the
same two bugs, and Exhibit A cost about four times more per run. The case for the extra cost is
what comes with each report and the false accusation it did not make, not better recall.

## The negative control had a false proof

The live compact run of `starlette-cve-2023-29159-fixed` ended with S3 `proven`. **That was a false
proof**: the test raced a symlink to the canary, and the oracle's check raced it in turn. The
oracle was fixed afterwards (`docs/oracle/oracle-provenance.md` section 3.8, `docs/bench/meta-run.md`), and the
fixed oracle rejects it. The recording's metadata still says `proven`.

The zero false accusations in the table therefore come from replaying through today's oracle, not
from what the live run concluded. Had the old oracle been scored, Exhibit A would show one false
accusation, the same as the naive reporter. Because S3 is a race, it can end `invalid_test` or
`discarded_unproven` from one replay to the next, but never `proven`, and neither outcome changes
a number in the table. This is also why cost and live spend differ on this target: the live run
went on to call the fixer and defender for the false proof, and the replay does not.

No live run of the negative control has been made since the oracle fix.

## Limits of this comparison

- **Very small sample.** Three paired targets, one model sample each, and a model that is not
  deterministic. A new live run can differ. Nothing here supports a statistical claim.
- **Exhibit A was tuned on these cases; the naive prompt was not.** The compact proof contract was
  written while looking at failures on these same cases. Two earlier compact attempts were
  overwritten: one proved nothing (US$0.12), one proved only the archive case (US$0.22)
  (`docs/bench/meta-run.md`). The oracle fix came from this same negative control. So recall 1.00 and
  zero false accusations are after tuning, with no held-out case. The naive prompt was recorded
  once, untuned.
- **Both systems are handed the right file.** Recall does not measure finding the vulnerable file
  in a repository.
- **The archive fixture gives away its answers.** Its comments say `BUG`, `Fix` and
  `INCOMPLETE fix`, and they reach both systems. The naive finding on `fixed_incomplete` literally
  says "Incomplete fix", so the naive results on the archive trees are weak evidence. The Starlette
  targets have no such comments.
- **The one false accusation is arguable.** It claims that `follow_symlink=True` lets a symlink
  escape the static root. That is not the CVE and needs a symlink already in the served directory,
  and the case lists no vulnerability, so it is scored as an accusation. Exhibit A raised the same
  idea (S2) and rejected it because the test itself planted the symlink.
- **Ground truth lists the known CVE only.** A finding outside it on a vulnerable tree would count
  as an FP even if it were real. None occurred in this run.
- **Matching is deliberately generous.** Any class containing `traversal` (or `zip slip`, `tar
  slip`) matches `path_traversal`, and duplicates would all count as TPs. This can only help
  whichever system repeats itself.
- **Exhibit A was not measured on the archive `fixed` and `fixed_incomplete` trees.** No recording
  exists for them, so they are out of the headline row and marked `-`.
- **`fixed_incomplete` is scored as still vulnerable, not as a negative control.** Its case says an
  absolute member path still escapes, so reporting traversal there is correct.
- **Cost uses the list price.** Every input token is metered at the full rate; cached input is not
  modelled. The two systems also produce different things: Exhibit A's cost buys an exploit, a fix
  and bypass checks, and the naive cost buys a list.
- **The proof standard has declared limits.** The oracle is isolated and resource-limited and still
  has open false-proof limits (`docs/oracle/oracle-provenance.md`, `docs/security/THREAT_MODEL.md`).
- **Costs are counted from model calls, not ledger totals.** Ledgers written before commit
  d8b68f2 stamped the adversary's one call on every `suspicion_raised` event and so charged it
  once per suspicion; the loop now charges it once. The comparison counts actual model calls
  either way, and these match the recordings.
