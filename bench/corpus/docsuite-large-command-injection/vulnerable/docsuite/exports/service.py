"""Export use cases."""

from ..storage.blobs import BlobStore
from .bundle import BundleWriter
from .formats import check_format, extension
from .renderer import render


class ExportService:
    """Queue exports, render them at once and remember the artifacts."""

    def __init__(self, documents, queue, exports_dir):
        self.documents = documents
        self.queue = queue
        self.bundles = BundleWriter(exports_dir)
        self.artifacts = BlobStore(exports_dir)

    def create_export(self, account_id, doc_id, name):
        """Render an export now, queue a bundle job, and return the job."""
        check_format(name)
        document = self.documents.require(doc_id)
        job = self.queue.submit(doc_id, name, account_id)
        if name == "bundle":
            artifact = self.bundles.write_bundle(document, ("txt", "html"))
        else:
            artifact = job.id + extension(name)
            self.artifacts.put(artifact, render(document, name))
        self.queue.complete(job.id, artifact)
        return self.queue.get(job.id)

    def get_export(self, job_id):
        """The job with this id as a plain mapping, or None."""
        job = self.queue.get(job_id)
        if job is None:
            return None
        return {"id": job.id, "document": job.document, "format": job.format,
                "state": job.state, "artifact": job.artifact,
                "requested_by": job.requested_by}

    def artifact_bytes(self, job_id):
        """The rendered bytes of a finished single-file export, or None."""
        job = self.queue.get(job_id)
        if job is None or job.state != "done" or job.format == "bundle":
            return None
        return self.artifacts.get(job.artifact)
