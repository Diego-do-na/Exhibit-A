"""Handing finished exports to the people who asked for them."""

from ..errors import NotFound


class DeliveryService:
    """Notify requesters when their export is ready."""

    def __init__(self, exports, notifications):
        self.exports = exports
        self.notifications = notifications

    def deliver(self, account, job_id):
        """Queue the ready message for a finished job and return the job."""
        job = self.exports.get_export(job_id)
        if job is None:
            raise NotFound(f"no such export: {job_id}")
        if job["state"] != "done":
            raise NotFound(f"export {job_id} is not ready")
        document = self.exports.documents.require(job["document"])
        message = self.notifications.export_ready(account, document.title,
                                                  job["format"])
        return {"job": job, "message": message}

    def redeliver(self, account, job_id):
        """Queue the ready message again (the artifact is kept)."""
        return self.deliver(account, job_id)
