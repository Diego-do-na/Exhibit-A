"""Catalog use cases between the routes and the repository."""

from shop.errors import ApiError
from shop.models import SearchCriteria
from shop.repository import ProductRepository


def search_catalog(term, categories, sort, descending, limit):
    """Run a search with already parsed request values."""
    criteria = SearchCriteria(
        term=term,
        categories=tuple(categories),
        sort=sort,
        descending=descending,
        limit=limit,
    )
    return criteria, ProductRepository().find(criteria)


def get_product(product_id):
    """Return one product or raise a 404."""
    product = ProductRepository().get(product_id)
    if product is None:
        raise ApiError(404, "no such product")
    return product


def list_categories():
    """Return the category names."""
    return ProductRepository().categories()
