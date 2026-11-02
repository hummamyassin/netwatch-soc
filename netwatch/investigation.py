"""Alert investigation workflow: statuses, notes and closure dispositions.

Each alert follows a simple SOC triage workflow:

    New  ->  Investigating  ->  Closed        (a closed alert can be reopened)

Closing requires a disposition, the analyst's conclusion:
    True Positive               the activity really was malicious or unwanted
    False Positive              the rule fired on activity it should not have matched
    Benign / Expected Activity  the rule worked, but the activity is known and allowed
    Inconclusive                there is not enough information to decide

Storage:
    Everything here lives in memory. The dashboard keeps one
    InvestigationStore per dataset in Streamlit's session state, which is
    NOT durable: statuses and notes are lost when the browser tab is
    reloaded, the session ends or the app restarts. There is deliberately no
    database at this stage.

No automation: nothing here blocks traffic, sends notifications or talks to
other systems. It only records an analyst's decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

NEW, INVESTIGATING, CLOSED = "New", "Investigating", "Closed"
STATUSES = (NEW, INVESTIGATING, CLOSED)
DISPOSITIONS = ("True Positive", "False Positive", "Benign / Expected Activity", "Inconclusive")
MAX_NOTE_LENGTH = 2000

# The only status changes the workflow allows. Each action is valid from exactly
# one status:  action -> (required status, new status, name recorded in the history)
TRANSITIONS = {
    "start": (NEW, INVESTIGATING, "Investigation started"),
    "close": (INVESTIGATING, CLOSED, "Closed"),
    "reopen": (CLOSED, INVESTIGATING, "Reopened"),
}


class WorkflowError(ValueError):
    """An action the workflow does not allow; the message explains why."""


@dataclass(frozen=True)
class Note:
    created_at: datetime   # UTC
    text: str


@dataclass(frozen=True)
class HistoryEntry:
    at: datetime           # UTC
    action: str            # "Investigation started", "Note added", "Closed", "Reopened"
    detail: str = ""       # e.g. the closure disposition


@dataclass
class Case:
    """Everything recorded about one alert."""

    alert_id: str
    status: str = NEW
    disposition: str | None = None
    notes: list[Note] = field(default_factory=list)
    history: list[HistoryEntry] = field(default_factory=list)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def clean_note(text: str) -> str:
    """Trim a note and check it is neither empty nor too long."""
    cleaned = (text or "").strip()
    if not cleaned:
        raise WorkflowError("A note cannot be empty.")
    if len(cleaned) > MAX_NOTE_LENGTH:
        raise WorkflowError(f"A note can be at most {MAX_NOTE_LENGTH} characters (this one has {len(cleaned)}).")
    return cleaned


class InvestigationStore:
    """Investigation state for the alerts of ONE dataset.

    Alerts nobody has touched are simply "New" and take no space. A case is
    stored the first time an action succeeds. Failed actions change nothing.
    """

    def __init__(self, dataset_id: str) -> None:
        self.dataset_id = dataset_id
        self._cases: dict[str, Case] = {}

    # -- reading ------------------------------------------------------------

    def case(self, alert_id: str) -> Case:
        """The recorded case, or a fresh "New" case (not stored) for an untouched alert."""
        return self._cases.get(alert_id) or Case(alert_id)

    def status(self, alert_id: str) -> str:
        case = self._cases.get(alert_id)
        return case.status if case else NEW

    def status_counts(self, alert_ids: list[str]) -> dict[str, int]:
        counts = {status: 0 for status in STATUSES}
        for alert_id in alert_ids:
            counts[self.status(alert_id)] += 1
        return counts

    def orphaned(self, current_alert_ids: list[str]) -> list[str]:
        """Cases whose alert is not in the current alert list (e.g. after changing thresholds)."""
        current = set(current_alert_ids)
        return sorted(alert_id for alert_id in self._cases if alert_id not in current)

    # -- actions ------------------------------------------------------------

    @staticmethod
    def _check_transition(case: Case, action: str) -> tuple[str, str]:
        """Return (new status, history label), or raise if the action is not allowed now."""
        required, new_status, label = TRANSITIONS[action]
        if case.status != required:
            raise WorkflowError(f"Cannot {action} an alert that is {case.status}; it must be {required}.")
        return new_status, label

    def start_investigation(self, alert_id: str, now: datetime | None = None) -> Case:
        case = self.case(alert_id)
        new_status, label = self._check_transition(case, "start")
        case.status = new_status
        case.history.append(HistoryEntry(now or _utc_now(), label))
        self._cases[alert_id] = case
        return case

    def add_note(self, alert_id: str, text: str, now: datetime | None = None) -> Case:
        case = self.case(alert_id)
        if case.status != INVESTIGATING:
            raise WorkflowError("Notes can only be added while an alert is being investigated. "
                                "Start the investigation (or reopen the alert) first.")
        note = Note(now or _utc_now(), clean_note(text))
        case.notes.append(note)
        case.history.append(HistoryEntry(note.created_at, "Note added"))
        self._cases[alert_id] = case
        return case

    def close(self, alert_id: str, disposition: str, note: str = "", now: datetime | None = None) -> Case:
        """Close an alert with a disposition and an optional closing note.

        Everything is checked before anything changes, so a failed close leaves
        the case exactly as it was.
        """
        if disposition not in DISPOSITIONS:
            raise WorkflowError(f"Choose one of the dispositions: {', '.join(DISPOSITIONS)}.")
        case = self.case(alert_id)
        new_status, label = self._check_transition(case, "close")
        closing_note = clean_note(note) if note and note.strip() else None

        moment = now or _utc_now()
        if closing_note:
            case.notes.append(Note(moment, closing_note))
            case.history.append(HistoryEntry(moment, "Note added"))
        case.status = new_status
        case.disposition = disposition
        case.history.append(HistoryEntry(moment, label, disposition))
        self._cases[alert_id] = case
        return case

    def reopen(self, alert_id: str, now: datetime | None = None) -> Case:
        """Move a closed alert back to Investigating. The old disposition stays in the history."""
        case = self.case(alert_id)
        new_status, label = self._check_transition(case, "reopen")
        previous = case.disposition or ""
        case.status = new_status
        case.disposition = None
        case.history.append(HistoryEntry(now or _utc_now(), label, f"was {previous}" if previous else ""))
        self._cases[alert_id] = case
        return case


def store_for(stores: dict[str, InvestigationStore], dataset_id: str) -> InvestigationStore:
    """The store of one dataset, created on first use.

    Every dataset (identified by a hash of its file content) gets its own
    store, so notes written for one uploaded log never show up on another.
    """
    if dataset_id not in stores:
        stores[dataset_id] = InvestigationStore(dataset_id)
    return stores[dataset_id]
