"""Turning result rows into response bodies."""


def revenue_rows(rows):
    """Rows of ``(period, orders, cents)`` as dictionaries."""
    return [{"period": period, "orders": orders, "revenue_cents": cents} for period, orders, cents in rows]


def part_rows(rows):
    """Rows of ``(part, orders)`` as dictionaries."""
    return [{"part": part, "orders": orders} for part, orders in rows]


def customer_rows(rows):
    """Rows of ``(customer, cents)`` as dictionaries."""
    return [{"customer": customer, "revenue_cents": cents} for customer, cents in rows]
