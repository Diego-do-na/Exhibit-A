def format_name(raw):
    return _normalise(raw).strip("/")


def _normalise(raw):
    return raw.lower()


def orphan(value):
    return open(value).read()
