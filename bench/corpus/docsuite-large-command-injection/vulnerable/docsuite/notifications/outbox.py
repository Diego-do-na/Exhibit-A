"""Queued messages kept as files below the outbox directory."""

import json
import os

from ..storage.paths import below
from ..util import dates, ids


class FileOutbox:
    """Store one JSON file per queued message."""

    def __init__(self, data_dir):
        self.directory = os.path.abspath(os.path.join(data_dir, "outbox"))
        os.makedirs(self.directory, exist_ok=True)

    def queue(self, account_id, subject, body):
        """Queue a message and return its id."""
        message_id = ids.next_id("msg")
        payload = {"id": message_id, "to": account_id, "subject": subject,
                   "body": body, "queued": dates.stamp(), "sent": None}
        with open(below(self.directory, message_id + ".json"), "w",
                  encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        return message_id

    def pending(self):
        """Every queued message that was not sent yet, oldest first."""
        queued = []
        for entry in sorted(os.listdir(self.directory)):
            if not entry.endswith(".json"):
                continue
            with open(os.path.join(self.directory, entry), encoding="utf-8") as handle:
                payload = json.load(handle)
            if payload.get("sent") is None:
                queued.append(payload)
        return queued

    def mark_sent(self, message_id):
        """Stamp a message sent; True when the message exists."""
        path = below(self.directory, message_id + ".json")
        if not os.path.isfile(path):
            return False
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        payload["sent"] = dates.stamp()
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        return True

    def count_pending(self):
        """How many messages wait to be sent."""
        return len(self.pending())
