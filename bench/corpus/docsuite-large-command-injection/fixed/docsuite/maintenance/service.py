"""Maintenance use cases."""

from . import archives, vacuum
from .checks import readiness
from .retention import select_targets, sweep
from .scheduler import describe as describe_schedule


class MaintenanceService:
    """Run retention cleanups and storage summaries."""

    def __init__(self, settings, recorder, history=None):
        self.settings = settings
        self.recorder = recorder
        self.history = history

    def run_cleanup(self, scope, target, actor=""):
        """Inventory the target, sweep temporary files and report what happened."""
        plan = select_targets(self.settings, scope, target)
        report = readiness(self.settings, scope, plan.directory)
        listing = archives.inventory(plan.directory, plan.target)
        removed = sweep(plan, self.recorder)
        line = archives.audit_line(plan.directory, plan.target, len(removed))
        self.recorder.record("cleanup", scope=scope, target=target,
                             removed=len(removed))
        entry = None
        if self.history is not None:
            entry = self.history.append(scope, target, removed, actor)
        return {"scope": scope, "target": target, "removed": removed,
                "listing": listing, "audit": line, "readiness": report,
                "recorded": entry is not None}

    def run_vacuum(self, scope):
        """Summarize a scope directory without changing it."""
        plan = select_targets(self.settings, scope, ".")
        summary = vacuum.summarize(plan.directory)
        self.recorder.record("vacuum", scope=scope, entries=summary["entries"])
        return summary

    def upkeep(self, scope, schedule):
        """The timetable and the current summary of a scope directory."""
        plan = select_targets(self.settings, scope, ".")
        return {"scope": scope, "schedule": describe_schedule(schedule),
                "summary": vacuum.summarize(plan.directory)}
