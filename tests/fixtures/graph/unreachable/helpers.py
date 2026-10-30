def format_name(raw):
    return raw.strip("/")


def orphan(value):
    return open(value).read()
