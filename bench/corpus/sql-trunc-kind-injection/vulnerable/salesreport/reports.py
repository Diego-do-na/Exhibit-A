"""The SQL behind the sales reports."""

PART_CODES = {"year": "%Y", "month": "%m", "day": "%d", "weekday": "%w"}


def revenue_by_period(conn, unit, since):
    """Orders and revenue per calendar period, for paid orders placed on or after ``since``."""
    query = (
        "SELECT date(placed_at, 'start of " + unit + "') AS period, COUNT(*), SUM(total_cents) "
        "FROM orders WHERE placed_at >= '" + since.isoformat() + "' AND status = 'paid' "
        "GROUP BY period ORDER BY period"
    )
    return conn.execute(query).fetchall()


def orders_by_part(conn, part, since):
    """How many paid orders fall on each value of a date part (month of the year, day of the week, ...)."""
    code = PART_CODES.get(part, part)
    query = (
        "SELECT CAST(strftime('" + code + "', placed_at) AS INTEGER) AS part, COUNT(*) "
        "FROM orders WHERE placed_at >= '" + since.isoformat() + "' AND status = 'paid' "
        "GROUP BY part ORDER BY part"
    )
    return conn.execute(query).fetchall()


def top_customers(conn, limit):
    """The customers with the highest paid revenue."""
    return conn.execute(
        "SELECT customer, SUM(total_cents) FROM orders WHERE status = 'paid' "
        "GROUP BY customer ORDER BY 2 DESC LIMIT ?",
        (limit,),
    ).fetchall()
