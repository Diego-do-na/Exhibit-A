"""The application: routes requests to the use cases."""

from .accounts import permissions
from .accounts.repository import AccountRepository
from .accounts.roles import profile as account_profile
from .accounts.service import AccountService
from .accounts.sessions import SessionStore
from .accounts.audit import LoginAudit
from .documents.activity import ActivityLog
from .documents.comments import CommentBoard
from .documents.pins import PinBoard
from .documents.repository import DocumentRepository
from .documents.service import DocumentService
from .documents.versions import VersionStore
from .errors import DocsuiteError
from .exports.delivery import DeliveryService
from .exports.queue import ExportQueue
from .exports.service import ExportService
from .http import auth, validators
from .http.caching import cache_headers, etag_for, not_modified
from .http.middleware import RequestContext, check_size, decorate
from .http.pagination import page_of, slice_items
from .http.ratelimit import RateLimiter
from .http.request import Request
from .http.response import Response, created, error, ok
from .http.router import match
from .logging_utils import Recorder, get_logger
from .maintenance.history import CleanupHistory
from .maintenance.service import MaintenanceService
from .notifications.outbox import FileOutbox
from .notifications.preferences import PreferenceStore
from .notifications.service import NotificationService
from .reports.service import ReportService
from .settings import build_settings
from .storage.backup import backup_scope, backups_for, prune_backups

LOG = get_logger("app")


class App:
    """Answer the document-suite routes with ``(status, payload)`` pairs."""

    def __init__(self, settings, accounts, documents, exports, delivery,
                 maintenance, notifications, reports, recorder):
        self.settings = settings
        self.account_service = AccountService(accounts)
        self.sessions = SessionStore(self.account_service.secret)
        self.logins = LoginAudit()
        self.limiter = RateLimiter()
        self.accounts = accounts
        self.documents = documents
        self.exports = exports
        self.delivery = delivery
        self.maintenance = maintenance
        self.notifications = notifications
        self.reports = reports
        self.recorder = recorder

    def handle_request(self, method, path, headers=None, body=b"", query=None):
        """Entry point: answer one request with a ``(status, payload)`` pair."""
        request = Request(method, path, headers, body, query)
        context = RequestContext()
        try:
            check_size(request, self.settings.max_body_bytes)
            remaining = self.limiter.check(request.bearer_token())
            name, params = match(request.method, request.path)
            if name is None:
                return self._answer(error(404, "not found"), context, remaining)
            if name == "405":
                return self._answer(error(405, "method not allowed"), context,
                                    remaining)
            if request.path != "/accounts/login":
                auth.authenticate(request, self.accounts)
            return self._answer(self._dispatch(request, name, params), context,
                                remaining)
        except DocsuiteError as failure:
            return self._answer(error(failure.status, str(failure)), context)

    def _answer(self, response, context, remaining=None):
        decorate(response, context)
        if remaining is not None:
            response.headers["x-ratelimit-remaining"] = str(remaining["remaining"])
        self.recorder.record("response", status=response.status)
        return response.status, response.body

    def _dispatch(self, request, name, params):
        if name == "accounts.login":
            return self._login(request)
        if name == "accounts.logout":
            return self._logout(request)
        if name == "accounts.me":
            return ok({"account": account_profile(request.account)})
        if name == "documents.list":
            return self._list_documents(request)
        if name == "documents.create":
            return self._create_document(request)
        if name == "documents.show":
            return self._show_document(request, params)
        if name == "documents.update":
            return self._update_document(request, params)
        if name == "documents.versions":
            return self._versions(request, params)
        if name == "documents.pin":
            return self._pin(request, params)
        if name == "documents.unpin":
            return self._unpin(request, params)
        if name == "pins.list":
            return self._pins(request)
        if name == "documents.related":
            return self._related(request, params)
        if name == "documents.search":
            return self._search(request)
        if name == "exports.create":
            return self._create_export(request)
        if name == "exports.show":
            return self._show_export(request, params)
        if name == "exports.deliver":
            return self._deliver(request, params)
        if name == "notifications.digest":
            return self._digest(request)
        if name == "notifications.preferences":
            return self._preferences(request)
        if name == "notifications.update_preferences":
            return self._update_preferences(request)
        if name == "notifications.flush":
            return self._flush(request)
        if name == "admin.usage":
            return self._usage(request)
        if name == "admin.cleanup":
            return self._cleanup(request)
        if name == "admin.backup":
            return self._backup(request)
        return error(404, "not found")

    def _login(self, request):
        from .errors import Unauthorized

        data = request.json()
        name = validators.require(data, "name")
        try:
            token = self.account_service.login(name, validators.require(data, "token"))
        except Unauthorized:
            self.logins.record(name, False)
            raise
        account = self.accounts.by_token(validators.require(data, "token"))
        self.sessions.open(account)
        self.logins.record(name, True)
        return ok({"session": token})

    def _logout(self, request):
        forgotten = self.sessions.close(request.bearer_token() or "")
        return ok({"logged_out": forgotten})

    def _list_documents(self, request):
        permissions.require(request.account, "documents.read")
        offset, size = page_of(request.query, self.settings.page_size)
        mine = request.query.get("mine")
        owner = request.account.id if str(mine).lower() in ("1", "true", "yes") else None
        items = self.documents.list_documents(owner)
        window = slice_items(items, offset, size)
        return ok({"documents": window["items"], "total": window["total"]})

    def _create_document(self, request):
        permissions.require(request.account, "documents.write")
        data = request.json()
        title = validators.clean_title(
            validators.require(data, "title"), self.settings.max_title)
        body = validators.require(data, "body")
        tags = validators.clean_tags(data.get("tags", []))
        if len(body.encode("utf-8")) > self.settings.max_body_bytes:
            raise DocsuiteError("the body is too large", status=413)
        document = self.documents.create_document(
            request.account.id, title, body, tags)
        self.recorder.record("document_created", id=document.id)
        return created({"document": document.to_dict()})

    def _show_document(self, request, params):
        permissions.require(request.account, "documents.read")
        payload = {"document": self.documents.get_document(params["id"])}
        tag = etag_for(repr(sorted(payload["document"].get("tags", []))).encode()
                       + payload["document"]["id"].encode())
        if not_modified(request, tag):
            return Response(304, {})
        response = ok(payload)
        response.headers.update(cache_headers(tag))
        return response

    def _pin(self, request, params):
        permissions.require(request.account, "documents.read")
        self.documents.repository.require(params["id"])
        return ok({"pinned": self.documents.pin(request.account.id, params["id"])})

    def _unpin(self, request, params):
        permissions.require(request.account, "documents.read")
        return ok({"unpinned": self.documents.unpin(request.account.id,
                                                    params["id"])})

    def _pins(self, request):
        permissions.require(request.account, "documents.read")
        return ok({"pins": self.documents.pinned_for(request.account.id)})

    def _update_document(self, request, params):
        permissions.require(request.account, "documents.write")
        data = request.json()
        title = data.get("title")
        if title is not None:
            title = validators.clean_title(title, self.settings.max_title)
        tags = None
        if "tags" in data:
            tags = validators.clean_tags(data["tags"])
        document = self.documents.update_document(
            params["id"], title=title, body=data.get("body"), tags=tags,
            actor=request.account.id)
        return ok({"document": document.to_dict()})

    def _versions(self, request, params):
        permissions.require(request.account, "documents.read")
        self.documents.repository.require(params["id"])
        return ok({"versions": self.documents.versions.history(params["id"])})

    def _related(self, request, params):
        permissions.require(request.account, "documents.read")
        return ok({"documents": self.documents.related(params["id"])})

    def _search(self, request):
        permissions.require(request.account, "documents.read")
        query = request.query.get("q", "")
        tag = request.query.get("tag", "")
        if tag:
            return ok({"documents": self.documents.by_tag(tag)})
        return ok({"documents": self.documents.search(query)})

    def _create_export(self, request):
        permissions.require(request.account, "exports.create")
        data = request.json()
        job = self.exports.create_export(
            request.account.id,
            validators.require(data, "document"),
            validators.choice(data.get("format", "txt"),
                               self.settings.export_formats, "format"),
        )
        return created({"job": self.exports.get_export(job.id)})

    def _show_export(self, request, params):
        permissions.require(request.account, "exports.create")
        job = self.exports.get_export(params["id"])
        if job is None:
            return error(404, "no such export")
        return ok({"job": job})

    def _deliver(self, request, params):
        permissions.require(request.account, "exports.create")
        return ok(self.delivery.deliver(request.account, params["id"]))

    def _digest(self, request):
        permissions.require(request.account, "notifications.read")
        message = self.notifications.digest_for(
            request.account, self.documents.repository.all(),
            self.exports.queue.list())
        return ok({"message": message})

    def _preferences(self, request):
        permissions.require(request.account, "notifications.read")
        return ok(self.notifications.preferences.describe(request.account.id))

    def _update_preferences(self, request):
        permissions.require(request.account, "notifications.write")
        data = request.json()
        store = self.notifications.preferences
        for kind in data.get("mute", []):
            store.mute(request.account.id, kind)
        for kind in data.get("unmute", []):
            store.unmute(request.account.id, kind)
        return ok(store.describe(request.account.id))

    def _flush(self, request):
        permissions.require(request.account, "notifications.write")
        return ok({"sent": self.notifications.flush()})

    def _usage(self, request):
        permissions.require(request.account, "admin.read")
        return ok(self.reports.admin_usage())

    def _cleanup(self, request):
        permissions.require(request.account, "admin.write")
        data = request.json()
        result = self.maintenance.run_cleanup(
            validators.require(data, "scope"), validators.require(data, "target"),
            actor=request.account.id)
        LOG.info("cleanup scope=%s target=%s removed=%d",
                 result["scope"], result["target"], len(result["removed"]))
        return ok(result)

    def _backup(self, request):
        permissions.require(request.account, "admin.write")
        data = request.json()
        scope = validators.choice(validators.require(data, "scope"),
                                   ("exports", "documents", "outbox"),
                                   "scope")
        plan = self.maintenance.run_vacuum(scope)
        result = backup_scope(scope, plan["directory"])
        pruned = prune_backups(plan["directory"])
        self.recorder.record("backup", scope=scope, backup=result["backup"])
        return created({"backup": result, "pruned": pruned,
                        "backups": backups_for(plan["directory"])})


def create_app(data_dir):
    """Build the document suite storing its data below ``data_dir``."""
    settings = build_settings(data_dir)
    settings.ensure_dirs()
    accounts = AccountRepository.seeded()
    board = CommentBoard()
    repository = DocumentRepository(data_dir)
    versions = VersionStore(data_dir)
    documents = DocumentService(repository, versions, board, ActivityLog(),
                                PinBoard())
    exports = ExportService(repository, ExportQueue(), settings.path("exports"))
    recorder = Recorder()
    maintenance = MaintenanceService(settings, recorder,
                                     CleanupHistory(data_dir))
    outbox = FileOutbox(data_dir)
    notifications = NotificationService(outbox, PreferenceStore())
    delivery = DeliveryService(exports, notifications)
    audit = LoginAudit()
    reports = ReportService(settings, accounts, repository, exports, audit)
    service = App(settings, accounts, documents, exports, delivery,
                  maintenance, notifications, reports, recorder)
    service.logins = audit
    return service
