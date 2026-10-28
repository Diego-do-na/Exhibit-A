"""Metrics computed from ledger events only."""

from dataclasses import dataclass

from exhibit_a.ledger import Ledger
from exhibit_a.schemas import EventType

from .corpus import Case


@dataclass
class CaseMetrics:
    reported: int = 0  # findings shown to the maintainer
    proven: int = 0  # findings with a proven verdict
    true_positives: int = 0
    false_positives: int = 0
    discarded: int = 0  # suspicions raised but never reported
    truth_total: int = 0  # known vulnerabilities in the case
    truth_found: int = 0
    tokens: int = 0
    cost_usd: float = 0.0


def case_metrics(ledger: Ledger, run_id: str, case: Case, naive: bool) -> CaseMetrics:
    """Score one run. Naive runs report every suspicion; others only proven verdicts."""
    suspicions: dict[str, dict] = {}
    proven_ids: list[str] = []
    # Read all events for this run so we can both discover proven ids and
    # attribute tokens/cost to proven suspicions only.
    events = list(ledger.replay(run_id))
    for event in events:
        if event.type == EventType.SUSPICION_RAISED:
            suspicions[event.payload["id"]] = event.payload
        elif event.type == EventType.VERDICT and event.payload.get("verdict") == "proven":
            proven_ids.append(event.payload["suspicion_id"])

    reported_ids = list(suspicions) if naive else proven_ids
    truth = {(t["class"], t["file"]) for t in case.ground_truth}
    found: set[tuple[str, str]] = set()
    true_pos = 0
    for sid in reported_ids:
        sus = suspicions.get(sid, {})
        key = (sus.get("class"), sus.get("location", {}).get("file"))
        if key in truth:
            true_pos += 1
            found.add(key)

    # Totals come from the ledger totals for the whole run. Per-proven metrics
    # are derived later (Row.tokens_per_proven and Row.cost_per_proven) as
    # totals / proven. The real cost of discarded suspicions and adversary work
    # is included in the totals (requirement).
    totals = ledger.totals(run_id)

    return CaseMetrics(
        reported=len(reported_ids),
        proven=len(proven_ids),
        true_positives=true_pos,
        false_positives=len(reported_ids) - true_pos,
        discarded=len(suspicions) - len(reported_ids),
        truth_total=len(truth),
        truth_found=len(found),
        tokens=totals["tokens_in"] + totals["tokens_out"],
        cost_usd=totals["cost_usd"],
    )


@dataclass
class Row:
    """One results-table row: one ablation over the whole corpus."""

    ablation: str
    reported: int = 0
    proven: int = 0
    false_positives: int = 0
    recall: float | None = None  # None when the corpus has no known vulnerability
    discarded: int = 0
    tokens: int = 0
    cost_usd: float = 0.0

    @property
    def tokens_per_proven(self) -> float | None:
        return self.tokens / self.proven if self.proven else None

    @property
    def cost_per_proven(self) -> float | None:
        return self.cost_usd / self.proven if self.proven else None


def aggregate(ablation: str, parts: list[CaseMetrics]) -> Row:
    truth = sum(p.truth_total for p in parts)
    return Row(
        ablation=ablation,
        reported=sum(p.reported for p in parts),
        proven=sum(p.proven for p in parts),
        false_positives=sum(p.false_positives for p in parts),
        recall=sum(p.truth_found for p in parts) / truth if truth else None,
        discarded=sum(p.discarded for p in parts),
        tokens=sum(p.tokens for p in parts),
        cost_usd=sum(p.cost_usd for p in parts),
    )


def _fmt(value: float | None, spec: str) -> str:
    return "n/a" if value is None else format(value, spec)


def render_table(rows: list[Row]) -> str:
    """Markdown results table. Cost/tokens per proven is n/a when nothing was proven."""
    header = (
        "| ablation | reported | proven | false positives | recall | discarded "
        "| tokens | cost (USD) | tokens/proven | cost/proven (USD) |"
    )
    lines = [header, "|" + "---|" * 10]
    for r in rows:
        lines.append(
            f"| {r.ablation} | {r.reported} | {r.proven} | {r.false_positives} "
            f"| {_fmt(r.recall, '.2f')} | {r.discarded} | {r.tokens} "
            f"| {r.cost_usd:.6f} | {_fmt(r.tokens_per_proven, '.0f')} "
            f"| {_fmt(r.cost_per_proven, '.6f')} |"
        )
    return "\n".join(lines) + "\n"
