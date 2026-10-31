"""Message texts with named placeholders."""

TEMPLATES = {
    "welcome": "Hello {name}, your {role} account is ready.",
    "export_ready": "Hello {name}, your {format} export of '{title}' is ready.",
    "cleanup_done": "Hello {name}, the {scope} cleanup removed {removed} file(s).",
    "quota_warning": "Hello {name}, you have used {percent}% of your quota.",
}


def render(kind, values):
    """The template ``kind`` with ``values`` filled in."""
    template = TEMPLATES.get(kind)
    if template is None:
        raise KeyError(f"unknown template: {kind}")
    try:
        return template.format(**values)
    except KeyError as missing:
        raise KeyError(f"template {kind} needs {missing}")


def available():
    """The names of the known templates, sorted."""
    return sorted(TEMPLATES)


def fields(kind):
    """The placeholder names template ``kind`` uses."""
    import string

    template = TEMPLATES.get(kind)
    if template is None:
        raise KeyError(f"unknown template: {kind}")
    return sorted(
        {name for _, name, _, _ in string.Formatter().parse(template) if name}
    )
