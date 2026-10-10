"""Ordinary source with no PII, credentials, or platform identifiers — a clean
baseline that must produce zero findings."""

from dataclasses import dataclass


@dataclass
class Widget:
    name: str
    quantity: int = 0

    def restock(self, amount: int) -> int:
        self.quantity += amount
        return self.quantity


def summarize(widgets: list[Widget]) -> dict[str, int]:
    return {w.name: w.quantity for w in widgets}


if __name__ == "__main__":
    items = [Widget("bolt", 10), Widget("washer", 25)]
    print(summarize(items))
