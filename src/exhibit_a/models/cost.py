"""Token pricing and the cumulative cost meter with a hard stop."""

import threading
from dataclasses import dataclass

from .errors import BudgetExceeded


@dataclass(frozen=True)
class Pricing:
    """USD per one million tokens."""

    input_per_mtok: float = 0.0
    output_per_mtok: float = 0.0

    def cost(self, tokens_in: int, tokens_out: int) -> float:
        return (
            tokens_in * self.input_per_mtok + tokens_out * self.output_per_mtok
        ) / 1_000_000


class CostMeter:
    """Tracks cumulative spend and refuses to go past `limit_usd`.

    The limit is a hard stop: once the total reaches it, `charge` raises and `check`
    keeps raising, so no further model call is started.
    """

    def __init__(self, limit_usd: float) -> None:
        if limit_usd <= 0:
            raise ValueError("limit_usd must be positive")
        self.limit_usd = limit_usd
        self._total = 0.0
        self._lock = threading.Lock()

    @property
    def total_usd(self) -> float:
        return self._total

    def check(self) -> None:
        """Raise BudgetExceeded if the limit is already reached."""
        if self._total >= self.limit_usd:
            raise BudgetExceeded(
                f"budget of ${self.limit_usd:.4f} reached (spent ${self._total:.4f})"
            )

    def charge(self, cost_usd: float) -> None:
        """Add a cost; raise BudgetExceeded if the total now reaches the limit."""
        if cost_usd < 0:
            raise ValueError("cost_usd must not be negative")
        with self._lock:
            self._total += cost_usd
        self.check()
