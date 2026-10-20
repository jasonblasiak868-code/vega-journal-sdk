"""Tests and attacks for the Q and A journal: verbatim storage, the hash chain, tampering, search, the thought genome, origin, receipts, the Merkle proofs."""
import json
import pathlib
import tempfile
import unittest

from vega_custody.dag.dag import Dag, DagError
from vega_journal import journal as J, merkle

T0 = 1_800_000_000


class Rig:
    def __init__(self):
        self.t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([self.t / "c.jsonl"], [self.t / "l.jsonl"])
        self.now = {"t": T0}
        self.path = self.t / "journal.jsonl"
        self.j = J.Journal(self.path, self.dag, clock=lambda: self.now["t"])

    def reopen(self):
        return J.Journal(self.path, self.dag, clock=lambda: self.now["t"])

    def tick(self, n=60):
        self.now["t"] += n


class Entries(unittest.TestCase):
    def test_text_is_kept_verbatim_and_each_record_links_to_the_one_before(self):
        r = Rig()
        text = "Why is the harmonic echo audible?  Spaces,\ttabs and é中文 stay as written.\n"
        a = r.j.add("owner", text)
        r.tick()
        b = r.j.add("model", "Because tracers make the layers audible.", kind="note")
        self.assertEqual(r.j.get(a["sha256"])["text"], text)
        self.assertEqual((a["i"], b["i"], b["prev"], a["prev"]), (0, 1, a["sha256"], "0" * 64))
        self.assertEqual(r.j.head, b["sha256"])
        self.assertEqual(r.j.add("owner", "second", session="s2")["session"], "s2")

    def test_input_is_checked(self):
        r = Rig()
        for kw in ({"speaker": "stranger", "text": "x"}, {"speaker": "owner", "text": ""}, {"speaker": "owner", "text": "   "}, {"speaker": "owner", "text": "a\x00b"},
                   {"speaker": "owner", "text": "x" * (J.MAX_TEXT + 1)}, {"speaker": "owner", "text": 5}, {"speaker": "owner", "text": "x", "session": ""}, {"speaker": "owner", "text": "x", "session": "a" * 81},
                   {"speaker": "owner", "text": "x", "session": "bad\nsession"}, {"speaker": "owner", "text": "x", "kind": "answer"}, {"speaker": "owner", "text": "x", "kind": "essay"}):
            with self.assertRaises(J.JournalRefused, msg=str(kw)[:60]):
                r.j.add(**kw)
        self.assertEqual(len(r.j.records), 0)

    def test_a_credential_is_never_written_but_the_original_is_vouched_for_by_its_hash(self):
        r = Rig()
        key = "sk-" + "aB3dE5gH" * 4
        e = r.j.add("owner", "my key is " + key)
        self.assertTrue(e["redacted"])
        self.assertNotIn(key, r.path.read_text())
        self.assertNotIn(key, json.dumps([x["payload"] for x in r.dag.content.entries()]))
        self.assertEqual(e["text"], J.MARK)
        import hashlib
        self.assertEqual(e["original_sha256"], hashlib.sha256(("my key is " + key).encode()).hexdigest())
        with self.assertRaises(J.JournalRefused):
            r.j.idea("secret idea", e["sha256"], 0, 3)

    def test_questions_and_answers(self):
        r = Rig()
        q = r.j.question("owner", "What is a jurisdictional key?")
        r.tick()
        q2 = r.j.question("owner", "Is the airlock one-way?")
        r.tick()
        a = r.j.answer(q["sha256"], "model", "A key held by a sovereign.")
        self.assertEqual(r.j.pairs(), [(q, a)])
        self.assertEqual([x["sha256"] for x in r.j.unanswered()], [q2["sha256"]])
        for bad in ("nosuch", None, a["sha256"], 5):
            with self.assertRaises(J.JournalRefused):
                r.j.answer(bad, "model", "x")


class Chain(unittest.TestCase):
    def setUp(self):
        self.r = Rig()
        for i in range(5):
            self.r.j.add("owner" if i % 2 else "model", "record number %d about the lattice" % i)
            self.r.tick()

    def lines(self):
        return self.r.path.read_text(encoding="utf-8").split("\n")[:-1]

    def test_a_clean_journal_reloads_and_verifies(self):
        j2 = self.r.reopen()
        self.assertEqual((len(j2.records), j2.head), (5, self.r.j.head))
        self.assertEqual(j2.verify(), (True, []))
        self.assertEqual(self.r.j.verify(), (True, []))

    def test_editing_deleting_reordering_or_cutting_is_caught_and_located(self):
        lines = self.lines()
        edits = {
            "edited text": lines[:2] + [lines[2].replace("record number 2", "record number X")] + lines[3:],
            "deleted line": lines[:2] + lines[3:],
            "reordered": [lines[1], lines[0]] + lines[2:],
            "duplicated": lines + [lines[-1]],
            "inserted junk": lines[:3] + ["{}"] + lines[3:],
            "not json": lines + ["garbage"],
        }
        for name, new in edits.items():
            self.r.path.write_text("\n".join(new) + "\n", encoding="utf-8")
            with self.assertRaises(J.JournalRefused, msg=name):
                self.r.reopen()
        self.r.path.write_text("\n".join(lines) + "\n" + lines[0][:20], encoding="utf-8")          # a half-written last line
        with self.assertRaises(J.JournalRefused):
            self.r.reopen()

    def test_a_splice_from_another_journal_and_a_renumbering_are_caught(self):
        other = Rig()
        for i in range(5):
            other.j.add("owner", "a different journal, record %d" % i)
            other.tick()
        mine = self.lines()
        theirs = other.path.read_text(encoding="utf-8").split("\n")[:-1]
        self.r.path.write_text("\n".join(mine[:3] + theirs[3:]) + "\n", encoding="utf-8")                 # every position and every hash is valid; only the links are wrong
        with self.assertRaises(J.JournalRefused):
            self.r.reopen()
        recs = [json.loads(x) for x in mine]
        recs[3]["i"] = 9
        recs[3]["sha256"] = J._hash(recs[3])
        recs[4]["prev"] = recs[3]["sha256"]
        recs[4]["sha256"] = J._hash(recs[4])
        self.r.path.write_text("\n".join(json.dumps(x, sort_keys=True, separators=(",", ":")) for x in recs) + "\n", encoding="utf-8")
        with self.assertRaises(J.JournalRefused):
            self.r.reopen()                                                                      # hashes and links are consistent; the positions are not

    def test_a_rewritten_chain_that_is_internally_consistent_still_fails_against_the_dag(self):
        import hashlib
        lines = self.lines()
        rec = json.loads(lines[-1])
        rec["text"] = "a rewritten last record"
        rec["sha256"] = J._hash(rec)                                                         # a forger recomputes the last hash
        self.r.path.write_text("\n".join(lines[:-1] + [json.dumps(rec, sort_keys=True, separators=(",", ":"))]) + "\n", encoding="utf-8")
        j2 = self.r.reopen()                                                                   # the file alone is consistent...
        ok, problems = j2.verify()                                                             # ...but the chain remembers the original hash
        self.assertFalse(ok)
        self.assertEqual(len(problems), 2)

    def test_a_record_in_the_chain_but_missing_from_the_file_is_reported(self):
        lines = self.lines()
        self.r.path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        ok, problems = self.r.reopen().verify()
        self.assertFalse(ok)
        self.assertIn("in the chain but not in the file", problems[0])

    def test_the_clock_cannot_run_backwards_and_equal_times_are_fine(self):
        self.r.now["t"] -= 10_000
        with self.assertRaises(J.JournalRefused):
            self.r.j.add("owner", "dated in the past")
        self.r.now["t"] = self.r.j.records[-1]["at"]
        self.r.j.add("owner", "same second")
        self.assertEqual(len(self.r.j.records), 6)

    def test_if_the_chain_cannot_be_written_nothing_is_recorded(self):
        before = self.r.path.read_text()
        real = self.r.dag.record

        def failing(kind, payload, parents=None):
            raise DagError("disk full")
        self.r.dag.record = failing
        with self.assertRaises(J.JournalRefused):
            self.r.j.add("owner", "this must not be recorded")
        self.r.dag.record = real
        self.assertEqual((self.r.path.read_text(), len(self.r.j.records)), (before, 5))
        self.r.j.add("owner", "now it can")
        self.assertEqual(self.r.j.verify(), (True, []))


class Search(unittest.TestCase):
    def setUp(self):
        self.r = Rig()
        for who, text in (("model", "The harmonic echo makes each layer audible."), ("owner", "What about the airlock between two gates?"), ("owner", "Tracers in the model make the echo audible."),
                          ("observer", "scaffolding text about the airlock"), ("owner", "A harmonic tune is a tuning target.")):
            self.r.j.add(who, text)
            self.r.tick()

    def test_ranking_filters_and_limits(self):
        hits = self.r.j.search("harmonic echo audible")
        self.assertEqual([h["text"][:12] for h in hits][:2], ["The harmonic", "Tracers in t"])
        self.assertEqual([h["speaker"] for h in self.r.j.search("airlock", speaker="owner")], ["owner"])
        self.assertEqual(self.r.j.search("zebra"), [])
        self.assertEqual(len(self.r.j.search("echo airlock tune", limit=2)), 2)
        for bad in (("x", 0), ("x", 101), ("x", True), (5, 5), (None, 5)):
            with self.assertRaises(J.JournalRefused):
                self.r.j.search(bad[0], limit=bad[1])

    def test_first_use_is_the_earliest_entry_holding_every_word(self):
        self.assertEqual(self.r.j.first_use("harmonic echo")["speaker"], "model")
        self.assertEqual(self.r.j.first_use("harmonic echo", speaker="owner"), None)
        self.assertEqual(self.r.j.first_use("echo audible", speaker="owner")["text"][:7], "Tracers")
        self.assertIsNone(self.r.j.first_use("quantum"))
        self.assertEqual(self.r.j.first_use("AIRLOCK")["speaker"], "owner")                         # case does not matter
        with self.assertRaises(J.JournalRefused):
            self.r.j.first_use("a !")


class Genome(unittest.TestCase):
    def setUp(self):
        self.r = Rig()
        self.text1 = "Maybe the tracers could make the model's parameters audible, like an engine hitting on all cylinders."
        self.e1 = self.r.j.add("model", self.text1)
        self.r.tick()
        self.text2 = "I want the harmonic echo: audible tracers as a tuning signal for any model."
        self.e2 = self.r.j.add("owner", self.text2)
        self.r.tick()
        self.text3 = "The airlock is a mantrap between two commitment gates."
        self.e3 = self.r.j.add("owner", self.text3)

    def quote(self, text, piece):
        s = text.index(piece)
        return s, s + len(piece)

    def test_an_idea_is_anchored_to_an_exact_quotation_and_the_quote_is_checked(self):
        s, e = self.quote(self.text2, "harmonic echo")
        rec = self.r.j.idea("Harmonic Echo", self.e2["sha256"], s, e)
        import hashlib
        self.assertEqual(rec["quote_sha256"], hashlib.sha256(b"harmonic echo").hexdigest())
        self.assertEqual(rec["origin"], "owner")
        for bad in ((5, 5), (6, 5), (-1, 5), (0, 10 ** 6), (True, 5), (0, True), ("a", 5)):
            with self.assertRaises(J.JournalRefused):
                self.r.j.anchor("harmonic echo", self.e2["sha256"], *bad)
        for name in ("", "a", "Has/Slash", "x" * 70, None, 5):
            with self.assertRaises(J.JournalRefused):
                self.r.j.idea(name, self.e2["sha256"], s, e)
        with self.assertRaises(J.JournalRefused):
            self.r.j.idea("harmonic echo", self.e2["sha256"], s, e)                                 # already exists (names ignore case)
        with self.assertRaises(J.JournalRefused):
            self.r.j.idea("other", "nosuch", 0, 3)
        with self.assertRaises(J.JournalRefused):
            self.r.j.anchor("never defined", self.e2["sha256"], 0, 3)

    def test_an_idea_cannot_grow_from_itself_and_is_told_so(self):
        s, e = self.quote(self.text2, "harmonic echo")
        self.r.j.idea("harmonic echo", self.e2["sha256"], s, e)
        with self.assertRaises(J.JournalRefused) as cm:
            self.r.j.derive("harmonic echo", "harmonic echo", self.e2["sha256"])
        self.assertIn("itself", str(cm.exception))

    def test_origin_is_who_said_it_and_a_models_suggestion_is_never_credited_to_the_owner(self):
        s1, e1 = self.quote(self.text1, "tracers could make the model's parameters audible")
        self.r.j.idea("audible tracers", self.e1["sha256"], s1, e1)
        self.assertEqual(self.r.j.first_anchor("audible tracers")["origin"], "model")
        with self.assertRaises(J.JournalRefused):
            self.r.j.conception_receipt("audible tracers")                                           # the owner has not said it
        s2, e2 = self.quote(self.text2, "audible tracers")
        self.r.j.anchor("audible tracers", self.e2["sha256"], s2, e2)
        self.assertEqual(self.r.j.first_anchor("audible tracers")["origin"], "model")                  # the earliest overall is still the model's
        rc = self.r.j.conception_receipt("audible tracers")
        self.assertEqual((rc["origin"], rc["entry_sha256"]), ("owner", self.e2["sha256"]))              # the receipt names the owner's own words
        self.assertTrue(J.verify_receipt(rc, "audible tracers"))
        self.assertEqual(self.r.j.conception_receipt("audible tracers", origin="model")["entry_sha256"], self.e1["sha256"])
        self.assertIsNone(self.r.j.first_anchor("audible tracers", "observer"))

    def test_the_earliest_anchor_wins_even_if_it_was_added_last(self):
        s3, e3 = self.quote(self.text3, "airlock")
        self.r.j.idea("airlock", self.e3["sha256"], s3, e3)                                        # first recorded against the LATER entry
        text = "An early note: the airlock idea started here."
        early = self.r.j.add("owner", text)                                                          # written after, but ... see below
        s, e = self.quote(text, "airlock")
        self.r.j.anchor("airlock", early["sha256"], s, e)
        self.assertEqual(self.r.j.first_anchor("airlock")["entry"], self.e3["sha256"])               # earliest by journal position is e3 (written before 'early')
        s1, e1 = self.quote(self.text1, "tracers")
        self.r.j.idea("tracers", self.e2["sha256"], *self.quote(self.text2, "tracers"))
        self.r.j.anchor("tracers", self.e1["sha256"], s1, e1)                                        # an earlier entry added as a later anchor
        self.assertEqual(self.r.j.first_anchor("tracers")["entry"], self.e1["sha256"])

    def test_first_use_among_many_matches_is_the_earliest(self):
        r = Rig()
        for i in range(15):
            r.j.add("owner", "entry %d mentions the lattice forecast" % i)
            r.tick()
        self.assertTrue(r.j.first_use("lattice forecast")["text"].startswith("entry 0 "))

    def test_ideas_grow_from_ideas_without_cycles(self):
        s, e = self.quote(self.text2, "harmonic echo")
        self.r.j.idea("harmonic echo", self.e2["sha256"], s, e)
        s, e = self.quote(self.text1, "tracers")
        self.r.j.idea("tracers", self.e1["sha256"], s, e)
        s, e = self.quote(self.text3, "airlock")
        self.r.j.idea("airlock", self.e3["sha256"], s, e)
        self.r.j.derive("harmonic echo", "tracers", self.e2["sha256"])
        self.r.j.derive("airlock", "harmonic echo", self.e3["sha256"])
        self.assertEqual([x["idea"] for x in self.r.j.lineage("airlock")], ["harmonic echo", "tracers"])
        self.assertEqual([x["origin"] for x in self.r.j.lineage("airlock")], ["owner", "model"])
        for child, parent in (("tracers", "airlock"), ("tracers", "harmonic echo"), ("airlock", "airlock")):
            with self.assertRaises(J.JournalRefused):
                self.r.j.derive(child, parent, self.e3["sha256"])
        with self.assertRaises(J.JournalRefused):
            self.r.j.derive("airlock", "nothing", self.e3["sha256"])
        with self.assertRaises(J.JournalRefused):
            self.r.j.lineage("nothing")

    def test_the_genome_survives_a_reload(self):
        s, e = self.quote(self.text2, "harmonic echo")
        self.r.j.idea("harmonic echo", self.e2["sha256"], s, e)
        s, e = self.quote(self.text1, "tracers")
        self.r.j.idea("tracers", self.e1["sha256"], s, e)
        self.r.j.derive("harmonic echo", "tracers", self.e2["sha256"])
        j2 = self.r.reopen()
        self.assertEqual([x["idea"] for x in j2.lineage("harmonic echo")], ["tracers"])
        self.assertEqual(j2.verify(), (True, []))


class Receipts(unittest.TestCase):
    def setUp(self):
        self.r = Rig()
        self.text = "The People's Veto pauses deployment when the roll reaches fifty-one percent."
        self.e = self.r.j.add("owner", self.text)
        s = self.text.index("People's Veto")
        self.r.j.idea("peoples veto", self.e["sha256"], s, s + len("People's Veto"))
        for i in range(9):
            self.r.tick()
            self.r.j.add("owner", "filler %d" % i)

    def test_a_receipt_checks_out_and_catches_every_alteration(self):
        rc = self.r.j.conception_receipt("peoples veto")
        self.assertTrue(J.verify_receipt(rc, "People's Veto"))
        self.assertTrue(J.verify_receipt(rc))
        self.assertFalse(J.verify_receipt(rc, "People's Vet0"))
        import copy
        for edit in (lambda d: d.update(journal_root="00" * 32), lambda d: d.update(entry_sha256="00" * 32), lambda d: d["proof"]["path"].reverse(),
                     lambda d: d["proof"]["path"].pop(), lambda d: d["proof"]["path"].__setitem__(0, ("X", d["proof"]["path"][0][1])), lambda d: d.pop("proof")):
            bad = copy.deepcopy(rc)
            edit(bad)
            self.assertFalse(J.verify_receipt(bad, "People's Veto"))
        for junk in (None, {}, "x", []):
            self.assertFalse(J.verify_receipt(junk))

    def test_an_old_receipt_stays_valid_against_its_own_root_after_the_journal_grows(self):
        rc = self.r.j.conception_receipt("peoples veto")
        self.r.tick()
        self.r.j.add("owner", "more")
        self.assertNotEqual(self.r.j.root(), rc["journal_root"])
        self.assertTrue(J.verify_receipt(rc))
        self.assertEqual(rc["journal_size"], 11)

    def test_inclusion_proofs(self):
        for rec in self.r.j.records:
            p = self.r.j.inclusion_proof(rec["sha256"])
            self.assertTrue(merkle.verify(self.r.j.root(), rec["sha256"], p["path"]))
        with self.assertRaises(J.JournalRefused):
            self.r.j.inclusion_proof("00" * 32)


class MerkleTests(unittest.TestCase):
    def test_every_leaf_of_every_size_proves_and_nothing_else_does(self):
        import hashlib
        for n in range(1, 21):
            hs = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(n)]
            rt = merkle.root(hs)
            for i in range(n):
                self.assertTrue(merkle.verify(rt, hs[i], merkle.proof(hs, i)), (n, i))
                self.assertFalse(merkle.verify(rt, hs[(i + 1) % n], merkle.proof(hs, i)) and n > 1)
            self.assertNotEqual(rt, merkle.root(hs[:-1]) if n > 1 else None)
        with self.assertRaises(IndexError):
            merkle.proof(["00" * 32], 1)
        self.assertEqual(len(merkle.root([])), 64)
        self.assertFalse(merkle.verify("00" * 32, "00" * 32, [("X", "00" * 32)]))
        self.assertFalse(merkle.verify("zz", "00" * 32, []))

    def test_leaves_and_nodes_are_hashed_with_different_prefixes(self):
        import hashlib
        x, y = hashlib.sha256(b"x").digest(), hashlib.sha256(b"y").digest()
        self.assertEqual(merkle._leaf(x), hashlib.sha256(bytes([0]) + x).digest())
        self.assertEqual(merkle._node(x, y), hashlib.sha256(bytes([1]) + x + y).digest())
        self.assertNotEqual(merkle._leaf(x), hashlib.sha256(x).digest())
        self.assertNotEqual(merkle._node(x, y), hashlib.sha256(x + y).digest())


if __name__ == "__main__":
    unittest.main()
