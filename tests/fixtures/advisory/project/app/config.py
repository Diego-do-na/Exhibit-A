"""Synthetic module: imports yamlish but never names the affected symbol."""

import yamlish


def read(text):
    return yamlish.safe_load(text)
