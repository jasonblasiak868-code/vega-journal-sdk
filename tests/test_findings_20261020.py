"""Regression tests (2026-10-20): the journal chose a record's position and previous hash, wrote the chain event, then appended to the file as separate steps with no lock and no
stale-writer check. Two concurrent writers (threads, or two objects on one file) both claimed the same position, broke the file's hash chain, and left a journal that refuses to open."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redteam_1_journal import Rig  # noqa: E402
from vega_journal import journal as J  # noqa: E402


def race(n, fn):
    gate, out, lock = threading.Barrier(n), [], threading.Lock()

    def go(i):
        gate.wait()
        try:
            fn(i)
            r = "ok"
        except J.JournalRefused:
            r = "refused"
        with lock:
            out.append(r)
    ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(60)
    return sorted(out)


def slow_chain(r, seconds=0.03):
    inner = r.dag.record

    class Slow:
        def __getattr__(self, k):
            return getattr(r.dag, k)

        def record(self, kind, payload, parents=None):
            time.sleep(seconds)
            return inner(kind, payload, parents)
    r.j.dag = Slow()


class WritesNeverForkTheFile(unittest.TestCase):
    def test_parallel_entries_all_land_in_one_unbroken_chain(self):
        r = Rig()
        slow_chain(r)
        res = race(8, lambda i: r.j.add("owner", "entry number %d" % i))
        self.assertEqual(res, ["ok"] * 8)
        again = r.reopen()                                            # would raise if the file's hash chain were broken
        self.assertEqual(len(again.records), 8)
        self.assertEqual([x["i"] for x in again.records], list(range(8)))
        self.assertEqual(r.j.verify(), (True, []))

    def test_two_journal_objects_on_one_file_do_not_both_append_blindly(self):
        r = Rig()
        r.j.add("owner", "first")
        other = r.reopen()
        slow_chain(r)
        res = race(2, lambda i: (r.j if i == 0 else other).add("owner", "from writer %d" % i))
        self.assertEqual(res, ["ok", "refused"])                      # the one with the stale view is refused, not written into a fork
        self.assertEqual(len(r.reopen().records), 2)

    def test_one_idea_name_is_created_once_under_concurrency(self):
        r = Rig()
        e = r.j.add("owner", "the harmonic echo is audible")
        slow_chain(r)
        self.assertEqual(race(3, lambda i: r.j.idea("harmonic echo", e["sha256"], 4, 17)), ["ok", "refused", "refused"])
        self.assertEqual(len([x for x in r.reopen().records if x["type"] == "idea"]), 1)


class PrivateJournalWritesNeverFork(unittest.TestCase):
    def test_parallel_private_entries_all_land_and_the_file_still_opens(self):
        from redteam_2_private import Rig as PRig
        r = PRig()
        inner = r.dag.record

        class Slow:
            def __getattr__(self, k):
                return getattr(r.dag, k)

            def record(self, kind, payload, parents=None):
                time.sleep(0.03)
                return inner(kind, payload, parents)
        r.j.dag = Slow()
        res = race(6, lambda i: r.j.add("owner", "private entry number %d" % i, session="s"))
        self.assertEqual(res, ["ok"] * 6)
        again = r.reopen(r.M)                                         # raises if the hash chain was broken
        self.assertEqual(len([x for x in again.records if x["type"] == "entry"]), 6)


if __name__ == "__main__":
    unittest.main()
