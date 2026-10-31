"""Request handlers and the route table."""

from shop import config, services
from shop.errors import ApiError
from shop.serializers import page_json, product_json
from shop.utils import as_list, clean_text, first, parse_int


def search_products(params):
    """GET /products: search the catalog."""
    term = clean_text(first(params.get("q")))
    categories = [clean_text(name) for name in as_list(params.get("category"))]
    sort = clean_text(first(params.get("sort"), config.DEFAULT_SORT))
    descending = first(params.get("order")).lower() == "desc"
    limit = parse_int(first(params.get("limit"), ""), config.DEFAULT_LIMIT, 1, config.MAX_LIMIT)
    criteria, products = services.search_catalog(term, categories, sort, descending, limit)
    return {"status": 200, "body": page_json(products, criteria)}


def show_product(params):
    """GET /products/<id>: one product."""
    product_id = parse_int(first(params.get("id")), 0, 0, 10**9)
    return {"status": 200, "body": {"product": product_json(services.get_product(product_id))}}


def show_categories(params):
    """GET /categories: the category names."""
    return {"status": 200, "body": {"categories": services.list_categories()}}


def dispatch(method, path, params):
    """Pick the handler for a request."""
    if method != "GET":
        raise ApiError(405, "method not allowed")
    if path == "/products":
        return search_products(params)
    if path == "/categories":
        return show_categories(params)
    if path.startswith("/products/"):
        return show_product({"id": path[len("/products/"):]})
    raise ApiError(404, "not found")
