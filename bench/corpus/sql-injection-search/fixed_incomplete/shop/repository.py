"""Catalog queries."""

import re
import sqlite3

from shop.db import session
from shop.errors import ApiError
from shop.models import Product


SORT_EXPRESSION = re.compile(r"[A-Za-z0-9_(), .<>=*+-]+")


def _screen(text):
    """Accept a sort made of identifier-like characters, so expressions such as lower(name) work."""
    if not SORT_EXPRESSION.fullmatch(text):
        raise ApiError(400, "unknown sort")
    return text


def _product(row):
    return Product(id=row[0], name=row[1], category=row[2], price_cents=row[3])


class ProductRepository:
    """Read products from the catalog database."""

    columns = "id, name, category, price_cents"

    def find(self, criteria):
        """Return the products that match a search, in the requested order."""
        clauses = []
        values = []
        if criteria.term:
            clauses.append("name LIKE ?")
            values.append("%" + criteria.term + "%")
        if criteria.categories:
            marks = ", ".join("?" for _ in criteria.categories)
            clauses.append("category IN (" + marks + ")")
            values.extend(criteria.categories)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        direction = "DESC" if criteria.descending else "ASC"
        statement = (
            "SELECT " + self.columns + " FROM products" + where
            + " ORDER BY " + _screen(criteria.sort) + " " + direction
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
