"""Background export jobs."""

from dataclasses import asdict, dataclass, field

from ..util import dates, ids


@dataclass
class ExportJob:
    """One requested export with its current state."""

    id: str
    document: str
    format: str
    requested_by: str
    state: str = "queued"
    created: str = ""
    finished: str = ""
    artifact: str = ""


class ExportQueue:
    """Requested exports, kept in memory."""

    def __init__(self):
        self._jobs = {}

    def submit(self, document_id, name, account_id):
        """Queue an export and return the job."""
        job = ExportJob(id=ids.next_id("job"), document=document_id, format=name,
                        requested_by=account_id, created=dates.stamp())
        self._jobs[job.id] = job
        return job

    def get(self, job_id):
        """The job with this id, or None."""
        return self._jobs.get(job_id)

    def complete(self, job_id, artifact):
        """Mark a job done and remember what it produced."""
        job = self._jobs.get(job_id)
        if job is None:
            return None
        job.state = "done"
        job.finished = dates.stamp()
        job.artifact = artifact
        return job

    def fail(self, job_id):
        """Mark a job failed."""
        job = self._jobs.get(job_id)
        if job is None:
            return None
        job.state = "failed"
        job.finished = dates.stamp()
        return job

    def list(self, state=None):
        """Every job, or only those in ``state``, as plain mappings."""
        jobs = list(self._jobs.values())
        if state is not None:
            jobs = [job for job in jobs if job.state == state]
        return [asdict(job) for job in jobs]

    def pending(self):
        """The queued jobs, oldest first."""
        return self.list("queued")
