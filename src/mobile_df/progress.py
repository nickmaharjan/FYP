"""Turn pipeline progress messages into a per-tool progress model for the desktop UI."""
import re
import time

from .adapters import ADAPTERS

# The order in which the pipeline runs adapters, so "skipped" is inferred correctly.
RUN_ORDER = tuple(adapter.name for adapter in ADAPTERS)
_RUNNING = re.compile(r"^Running (\w+)$")
_FINISHED = re.compile(r"^(\w+): (\w+) \((\d+) findings\)$")
DONE_STATES = {"success", "partial", "failed", "timeout", "cancelled", "skipped"}


class ProgressModel:
    """Tracks analysis stages. Tools that never start (not applicable to the evidence) become 'skipped'."""

    def __init__(self, tools, clock=time.monotonic):
        self.tools = [name for name in RUN_ORDER if name in set(tools)]
        self.states = {name: "waiting" for name in self.tools}
        self.findings = {name: 0 for name in self.tools}
        self.stage = "Starting"
        self.finished = False
        self.failed = False
        self._clock = clock
        self._start = clock()
        self._units_done = 0  # hash, copy, verify, report

    @property
    def total_units(self):
        return 4 + len(self.tools)

    @property
    def fraction(self):
        tools_done = sum(state in DONE_STATES for state in self.states.values())
        return 1.0 if self.finished else min(0.99, (self._units_done + tools_done) / self.total_units)

    @property
    def elapsed_seconds(self):
        return int(self._clock() - self._start)

    def _skip_waiting(self, before=None):
        for name in self.tools:
            if before is not None and self.tools.index(name) >= self.tools.index(before):
                break
            if self.states[name] == "waiting":
                self.states[name] = "skipped"

    def update(self, message):
        """Apply one pipeline message. Unknown messages only change the stage text."""
        self.stage = message
        if message == "Hashing original evidence":
            return
        if message == "Creating and verifying working copy":
            self._units_done = 1
            return
        running = _RUNNING.match(message)
        if running and running.group(1) in self.states:
            self._units_done = max(self._units_done, 2)
            self._skip_waiting(before=running.group(1))
            self.states[running.group(1)] = "running"
            return
        finished = _FINISHED.match(message)
        if finished and finished.group(1) in self.states:
            self.states[finished.group(1)] = finished.group(2)
            self.findings[finished.group(1)] = int(finished.group(3))
            return
        if message == "Verifying original evidence after analysis":
            self._units_done = 3
            self._skip_waiting()
            return
        if message.startswith("Case failed"):
            self.failed = True
            self._skip_waiting()
            return
        if message.startswith("Case ") and message.endswith("report saved"):
            self._units_done = 4
            self._skip_waiting()
            self.finished = True

    def rows(self):
        return [(name, self.states[name], self.findings[name]) for name in self.tools]
