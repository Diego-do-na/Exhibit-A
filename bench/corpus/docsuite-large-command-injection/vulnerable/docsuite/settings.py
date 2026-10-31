"""Settings of one running service."""

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    """Where data lives and the limits the service applies."""

    data_dir: str
    max_title: int = 120
    max_body_bytes: int = 200_000
    page_size: int = 20
    max_versions: int = 25
    export_formats: tuple = ("txt", "html", "bundle")
    extras: dict = field(default_factory=dict)

    def path(self, *parts):
        """A path below the data directory."""
        return os.path.join(self.data_dir, *parts)

    def ensure_dirs(self):
        """Create the directories the service writes to."""
        for name in ("blobs", "exports", "outbox", "cache", "audit", "backups"):
            os.makedirs(self.path(name), exist_ok=True)


def load_overrides(data_dir):
    """Read ``key=value`` lines from ``settings.conf`` in the data directory, if there is one."""
    overrides = {}
    path = os.path.join(data_dir, "settings.conf")
    if not os.path.isfile(path):
        return overrides
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                overrides[key.strip()] = value.strip()
    return overrides


def build_settings(data_dir):
    """Settings for ``data_dir`` with the overrides of its ``settings.conf`` applied."""
    settings = Settings(data_dir=data_dir)
    for key, value in load_overrides(data_dir).items():
        if key in ("max_title", "max_body_bytes", "page_size", "max_versions"):
            setattr(settings, key, int(value))
        else:
            settings.extras[key] = value
    return settings
