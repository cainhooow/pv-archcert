"""Small integer-cent ledger: deterministic totals without floating-point money."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Entry:
    reference: str
    cents: int

    def __post_init__(self):
        if not self.reference or type(self.cents) is not int:
            raise ValueError("reference and integer cents required")


def balance(entries: list[Entry]) -> int:
    """Sum unique references, rejecting duplicate postings rather than double billing."""
    references = set()
    total = 0
    for entry in entries:
        if entry.reference in references:
            raise ValueError("duplicate posting reference")
        references.add(entry.reference)
        total += entry.cents
    return total
