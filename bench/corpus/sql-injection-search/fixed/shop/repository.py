"""Catalog queries."""

import sqlite3

from shop.db import session
from shop.errors import ApiError
from shop.models import Product

SORT_COLUMNS = {
    "id": "id",
    "name": "name",
    "category": "category",
    "price_cents": "price_cents",
}


def _product(row):
    return Product(id=row[0], name=row[1], category=row[2], price_cents=row[3])


def _like_pattern(term):
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + escaped + "%"


class ProductRepository:
    """Read products from the catalog database."""

    columns = "id, name, category, price_cents"

    def find(self, criteria):
        """Return the products that match a search, in the requested order."""
        column = SORT_COLUMNS.get(criteria.sort)
        if column is None:
            raise ApiError(400, "unknown sort")
        clauses = []
        values = []
        if criteria.term:
            clauses.append("name LIKE ? ESCAPE '\\'")
            values.append(_like_pattern(criteria.term))
        if criteria.categories:
            marks = ", ".join("?" for _ in criteria.categories)
            clauses.append("category IN (" + marks + ")")
            values.extend(criteria.categories)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        direction = "DESC" if criteria.descending else "ASC"
        statement = (
            "SELECT " + self.columns + " FROM products" + where
            + " ORDER BY " + column + " " + direction
            + " LIMIT ?"
        )
        values.append(int(criteria.limit))
        with session() as conn:
            try:
                rows = conn.execute(statement, values).fetchall()
            except sqlite3.Error:
                raise ApiError(500, "search failed") from None
        return [_product(row) for row in rows]

    def get(self, product_id):
        """Return one product by id, or None."""
        with session() as conn:
            row = conn.execute(
                "SELECT " + self.columns + " FROM products WHERE id = ?", (int(product_id),)
            ).fetchone()
        return _product(row) if row else None

    def categories(self):
        """Return the distinct category names."""
        with session() as conn:
            rows = conn.execute("SELECT DISTINCT category FROM products ORDER BY category").fetchall()
        return [row[0] for row in rows]
