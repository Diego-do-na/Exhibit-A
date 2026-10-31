"""Turn models into response bodies."""


def product_json(product):
    """One product as a response mapping."""
    return {
        "id": product.id,
        "name": product.name,
        "category": product.category,
        "price_cents": product.price_cents,
    }


def page_json(products, criteria):
    """A search result page as a response mapping."""
    return {
        "count": len(products),
        "items": [product_json(product) for product in products],
    }
