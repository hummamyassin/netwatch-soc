"""Tests for netwatch.investigation (alert triage workflow), independent of the UI.

Run with:  python -m unittest -v
"""

import unittest
from datetime import datetime, timedelta, timezone

from netwatch import investigation as inv

T0 = datetime(2025, 3, 10, 9, 0, 0, tzinfo=timezone.utc)
ALERT = "NW-001-e76a1be8a006"


def at(minutes: int) -> datetime:
    return T0 + timedelta(minutes=minutes)


class StatusTransitionTests(unittest.TestCase):
    def setUp(self):
        self.store = inv.InvestigationStore("dataset-a")

    def test_untouched_alert_is_new_and_not_stored(self):
        self.assertEqual(self.store.status(ALERT), inv.NEW)
        self.assertEqual(self.store.case(ALERT).status, inv.NEW)
        self.assertEqual(self.store.orphaned([]), [])  # reading created nothing

    def test_full_workflow(self):
        self.store.start_investigation(ALERT, now=at(1))
        self.assertEqual(self.store.status(ALERT), inv.INVESTIGATING)
        self.store.add_note(ALERT, "  Source is an external host.  ", now=at(2))
        case = self.store.close(ALERT, "True Positive", note="Blocked at the firewall by the network team.", now=at(3))
        self.assertEqual((case.status, case.disposition), (inv.CLOSED, "True Positive"))
        self.assertEqual([n.text for n in case.notes],
                         ["Source is an external host.", "Blocked at the firewall by the network team."])
        self.assertEqual([(h.at, h.action, h.detail) for h in case.history], [
            (at(1), "Investigation started", ""),
            (at(2), "Note added", ""),
            (at(3), "Note added", ""),
            (at(3), "Closed", "True Positive"),
        ])

    def test_new_alert_cannot_be_closed_directly(self):
        with self.assertRaisesRegex(inv.WorkflowError, "Cannot close an alert that is New"):
            self.store.close(ALERT, "False Positive")
        self.assertEqual(self.store.status(ALERT), inv.NEW)

    def test_invalid_repeated_transitions(self):
        self.store.start_investigation(ALERT)
        with self.assertRaises(inv.WorkflowError):
            self.store.start_investigation(ALERT)
        self.store.close(ALERT, "Inconclusive")
        with self.assertRaises(inv.WorkflowError):
            self.store.close(ALERT, "Inconclusive")
        with self.assertRaises(inv.WorkflowError):
            self.store.start_investigation(ALERT)  # closed alerts are reopened, not restarted
        case = self.store.case(ALERT)
        self.assertEqual((case.status, case.disposition), (inv.CLOSED, "Inconclusive"))  # unchanged

    def test_reopen(self):
        self.store.start_investigation(ALERT, now=at(1))
        self.store.close(ALERT, "False Positive", now=at(2))
        case = self.store.reopen(ALERT, now=at(3))
        self.assertEqual((case.status, case.disposition), (inv.INVESTIGATING, None))
        self.assertEqual((case.history[-1].action, case.history[-1].detail), ("Reopened", "was False Positive"))
        with self.assertRaises(inv.WorkflowError):
            self.store.reopen(ALERT)  # only closed alerts can be reopened

    def test_every_disposition_is_accepted(self):
        for n, disposition in enumerate(inv.DISPOSITIONS):
            with self.subTest(disposition=disposition):
                alert_id = f"NW-002-{n:012d}"
                self.store.start_investigation(alert_id)
                self.assertEqual(self.store.close(alert_id, disposition).disposition, disposition)
        self.assertEqual(inv.DISPOSITIONS, ("True Positive", "False Positive", "Benign / Expected Activity",
                                            "Inconclusive"))

    def test_unknown_disposition_changes_nothing(self):
        self.store.start_investigation(ALERT)
        with self.assertRaisesRegex(inv.WorkflowError, "Choose one of the dispositions"):
            self.store.close(ALERT, "Probably fine")
        self.assertEqual(self.store.status(ALERT), inv.INVESTIGATING)


class NoteTests(unittest.TestCase):
    def setUp(self):
        self.store = inv.InvestigationStore("dataset-a")

    def test_notes_need_an_active_investigation(self):
        with self.assertRaisesRegex(inv.WorkflowError, "Start the investigation"):
            self.store.add_note(ALERT, "too early")
        self.store.start_investigation(ALERT)
        self.store.close(ALERT, "Inconclusive")
        with self.assertRaises(inv.WorkflowError):
            self.store.add_note(ALERT, "too late")

    def test_empty_and_long_notes_are_rejected(self):
        self.store.start_investigation(ALERT)
        for text in ["", "   ", "\n\t", None]:
            with self.subTest(text=text):
                with self.assertRaisesRegex(inv.WorkflowError, "empty"):
                    self.store.add_note(ALERT, text)
        self.store.add_note(ALERT, "x" * inv.MAX_NOTE_LENGTH)  # exactly the limit is fine
        with self.assertRaisesRegex(inv.WorkflowError, "at most"):
            self.store.add_note(ALERT, "x" * (inv.MAX_NOTE_LENGTH + 1))
        self.assertEqual(len(self.store.case(ALERT).notes), 1)

    def test_failed_close_keeps_the_case_unchanged(self):
        self.store.start_investigation(ALERT)
        with self.assertRaises(inv.WorkflowError):
            self.store.close(ALERT, "True Positive", note="x" * (inv.MAX_NOTE_LENGTH + 1))
        case = self.store.case(ALERT)
        self.assertEqual((case.status, case.disposition, case.notes), (inv.INVESTIGATING, None, []))

    def test_note_text_is_kept_verbatim(self):
        self.store.start_investigation(ALERT)
        text = "[link](http://example.com) **bold** <b>html</b>"
        self.assertEqual(self.store.add_note(ALERT, text).notes[-1].text, text)

    def test_default_timestamps_are_utc(self):
        self.store.start_investigation(ALERT)
        note_time = self.store.add_note(ALERT, "checked").notes[-1].created_at
        self.assertEqual(note_time.utcoffset(), timedelta(0))


class DatasetIsolationTests(unittest.TestCase):
    def test_each_dataset_has_its_own_store(self):
        stores: dict[str, inv.InvestigationStore] = {}
        first = inv.store_for(stores, "dataset-a")
        first.start_investigation(ALERT)
        second = inv.store_for(stores, "dataset-b")
        self.assertIsNot(first, second)
        self.assertEqual(second.status(ALERT), inv.NEW)  # same alert ID, different dataset
        self.assertIs(inv.store_for(stores, "dataset-a"), first)
        self.assertEqual(inv.store_for(stores, "dataset-a").status(ALERT), inv.INVESTIGATING)

    def test_status_counts_and_orphans(self):
        store = inv.InvestigationStore("dataset-a")
        store.start_investigation("NW-001-aaaaaaaaaaaa")
        store.start_investigation("NW-004-bbbbbbbbbbbb")
        store.close("NW-004-bbbbbbbbbbbb", "Benign / Expected Activity")
        current = ["NW-001-aaaaaaaaaaaa", "NW-002-cccccccccccc"]
        self.assertEqual(store.status_counts(current), {"New": 1, "Investigating": 1, "Closed": 0})
        self.assertEqual(store.orphaned(current), ["NW-004-bbbbbbbbbbbb"])


if __name__ == "__main__":
    unittest.main()
