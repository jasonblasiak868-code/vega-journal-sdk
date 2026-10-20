"""Tests and attacks for the private journal: encryption at rest, owner-only, grants, grounded answers, the legacy policy after death, and last-rites wishes."""
import copy
import json
import pathlib
import tempfile
import unittest

from vega_custody.dag.dag import Dag, DagError
from vega_journal import crypto, grounded as G, journal as JM, last_rites as LR, merkle, private as P
from vega_journal.journal import JournalRefused

T0 = 1_900_000_000
DAY = 86400


class Rig:
    def __init__(self):
        self.t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([self.t / "c.jsonl"], [self.t / "l.jsonl"])
        self.now = {"t": T0}
        self.owner, self.M = crypto.Signer(), crypto.new_key()
        self.path = self.t / "j.jsonl"
        self.j = P.PrivateJournal(self.path, self.dag, self.owner.public, self.M, clock=lambda: self.now["t"])
        self.j.initialise(self.owner)

    def tick(self, n=60):
        self.now["t"] += n

    def reopen(self, master=None):
        return P.PrivateJournal(self.path, self.dag, self.owner.public, master, clock=lambda: self.now["t"])

    def person(self):
        return crypto.Signer(), crypto.KeyPair()

    def fill(self):
        """A few entries across sessions and tags."""
        out = {}
        for key, (who, text, session, tags) in {
            "guitar": ("owner", "I want my sister Anna to have my guitar. She always loved it.", "wishes", ["family"]),
            "house": ("owner", "The house should be sold. The money should be split between Anna and Ben.", "wishes", ["family", "money"]),
            "recipe": ("owner", "Grandma's soup needs plenty of salt and a long slow simmer.", "kitchen", ["food"]),
            "model": ("model", "You might consider a different guitar for the band.", "chat", []),
            "work": ("owner", "The quarterly report is due on Friday.", "work", ["work"]),
        }.items():
            out[key] = self.j.add(who, text, session=session, tags=tags)
            self.tick()
        return out


class Encryption(unittest.TestCase):
    def test_the_file_holds_no_plaintext_and_a_locked_open_reads_nothing(self):
        r = Rig()
        e = r.fill()
        raw = r.path.read_text()
        for word in ("guitar", "Anna", "soup", "house", "quarterly"):
            self.assertNotIn(word, raw)
        locked = r.reopen(None)
        self.assertEqual(locked.verify(), (True, []))
        self.assertEqual(len(locked.records), len(r.j.records))
        with self.assertRaises(P.Locked):
            locked.read(e["guitar"]["sha256"])
        with self.assertRaises(P.Locked):
            locked.add("owner", "x")
        self.assertEqual(locked.search("guitar"), [])
        wrong = r.reopen(crypto.new_key())
        with self.assertRaises(Exception):
            wrong.read(e["guitar"]["sha256"])
        self.assertEqual(r.reopen(r.M).read(e["guitar"]["sha256"])["text"], "I want my sister Anna to have my guitar. She always loved it.")

    def test_search_works_for_the_owner_after_unlock_and_the_index_is_never_written(self):
        r = Rig()
        e = r.fill()
        j2 = r.reopen(r.M)
        j2.unlock_for_search()
        self.assertEqual(j2.search("guitar")[0]["sha256"], e["guitar"]["sha256"])
        self.assertNotIn("guitar", r.path.read_text())

    def test_a_ciphertext_cannot_be_moved_to_another_place_or_edited(self):
        r = Rig()
        e = r.fill()
        lines = r.path.read_text().split("\n")[:-1]
        recs = [json.loads(x) for x in lines]
        a, b = recs[1], recs[2]
        a["ct"], b["ct"] = b["ct"], a["ct"]                                          # swap two entries' ciphertext, then re-chain the hashes so the chain itself is fine
        a["nonce"], b["nonce"] = b["nonce"], a["nonce"]
        prev = recs[0]["sha256"]
        for k in range(1, len(recs)):
            recs[k]["prev"] = prev
            recs[k]["sha256"] = JM._hash(recs[k])
            prev = recs[k]["sha256"]
        r.path.write_text("\n".join(json.dumps(x, sort_keys=True, separators=(",", ":")) for x in recs) + "\n")
        with self.assertRaises(JournalRefused):                                              # the owner's key opens the file and the altered entries do not decrypt
            r.reopen(r.M).unlock_for_search()

    def test_another_owners_journal_and_a_second_initialise_are_refused(self):
        r = Rig()
        stranger = crypto.Signer()
        with self.assertRaises(JournalRefused):
            P.PrivateJournal(r.path, r.dag, stranger.public, None, clock=lambda: T0)
        with self.assertRaises(JournalRefused):
            r.j.initialise(r.owner)
        fresh = P.PrivateJournal(r.t / "other.jsonl", r.dag, r.owner.public, r.M, clock=lambda: T0)
        with self.assertRaises(JournalRefused):
            fresh.initialise(stranger)                                                    # not the owner's signer
        with self.assertRaises(P.Locked):
            P.PrivateJournal(r.t / "o2.jsonl", r.dag, r.owner.public, None).initialise(r.owner)
        with self.assertRaises(JournalRefused):
            P.PrivateJournal(r.t / "o3.jsonl", r.dag, r.owner.public, r.M).add("owner", "before init")

    def test_inputs_credentials_media_and_tags_are_checked(self):
        r = Rig()
        for kw in ({"speaker": "stranger", "text": "x"}, {"speaker": "owner", "text": ""}, {"speaker": "owner", "text": "a\x00b"}, {"speaker": "owner", "text": "x", "tags": ["t%d" % i for i in range(21)]},
                   {"speaker": "owner", "text": "x", "tags": [""]}, {"speaker": "owner", "text": "x", "session": ""}, {"speaker": "owner", "text": "x", "kind": "wish"}, {"speaker": "owner", "text": "x", "kind": "answer"}):
            with self.assertRaises(JournalRefused, msg=str(kw)):
                r.j.add(**kw)
        red = r.j.add("owner", "my key is sk-" + "aB3dE5gH" * 4)
        self.assertTrue(red["redacted"])
        self.assertEqual(r.j.read(red["sha256"])["text"], P.MARK)
        sha = "ab" * 32
        good = {"type": "video", "sha256": sha, "bytes": 1000, "segments": [{"start_ms": 0, "end_ms": 1000, "text": "Hello there."}, {"start_ms": 1000, "end_ms": 2500, "text": "Second thing."}]}
        v = r.j.add("owner", "", media=good)
        self.assertEqual(r.j.read(v["sha256"])["segments"][1]["text"], "Second thing.")
        for bad in (dict(good, type="gif"), dict(good, sha256="x"), dict(good, bytes=0), dict(good, segments=[]), dict(good, segments=[{"start_ms": 5, "end_ms": 5, "text": "x"}]),
                    dict(good, segments=[{"start_ms": 0, "end_ms": 10, "text": "a"}, {"start_ms": 5, "end_ms": 20, "text": "b"}]), dict(good, segments=[{"start_ms": 0, "end_ms": 10, "text": " "}]), "video"):
            with self.assertRaises(JournalRefused):
                r.j.add("owner", "", media=bad)
        q = r.j.question("owner", "What is the plan?", tags=["x"])
        a = r.j.answer(q["sha256"], "owner", "Keep it simple.")
        self.assertEqual(r.j.pairs()[0][1]["sha256"], a["sha256"])

    def test_ideas_can_be_anchored_in_private_text(self):
        r = Rig()
        e = r.fill()
        text = r.j.read(e["recipe"]["sha256"])["text"]
        s = text.index("slow simmer")
        rec = r.j.idea("slow simmer", e["recipe"]["sha256"], s, s + len("slow simmer"))
        self.assertEqual(rec["origin"], "owner")
        self.assertEqual(r.reopen(r.M).conception_receipt("slow simmer")["origin"], "owner")


class CryptoLimits(unittest.TestCase):
    def test_splits_and_wraps_have_limits(self):
        for k, n in ((1, 3), (3, 2), (2, 17), (True, 3)):
            with self.assertRaises((crypto.CryptoRefused, TypeError)):
                crypto.split(crypto.new_key(), k, n)
        for bad in (b"", b"x" * 1025, "text", None):
            with self.assertRaises(crypto.CryptoRefused):
                crypto.wrap_for(crypto.KeyPair().public, bad)
        kp = crypto.KeyPair()
        self.assertEqual(kp.unwrap(crypto.wrap_for(kp.public, b"y" * 33)), b"y" * 33)
        shares, check = crypto.split(crypto.new_key(), 2, 3)
        with self.assertRaises(crypto.CryptoRefused):
            crypto.combine(shares[:1], check, 2, 3)
        with self.assertRaises(crypto.CryptoRefused):
            crypto.combine([shares[0], (shares[1][0], bytes(32))], check, 2, 3)


class Grants(unittest.TestCase):
    def setUp(self):
        self.r = Rig()
        self.e = self.r.fill()
        self.sign, self.box = self.r.person()

    def test_a_full_grant_delivers_exactly_the_scope_to_the_grantees_own_key(self):
        r = self.r
        gid = r.j.grant(self.sign.public, self.box.public, "full", {"kind": "sessions", "sessions": ["wishes"]}, r.owner)
        got = r.j.grantee_open(gid, self.box)
        self.assertEqual(set(got), {self.e["guitar"]["sha256"], self.e["house"]["sha256"]})
        self.assertIn("guitar", got[self.e["guitar"]["sha256"]]["text"])
        other = crypto.KeyPair()
        with self.assertRaises(JournalRefused):
            r.j.grantee_open(gid, other)                                                # the wrong box key
        j2 = r.reopen(None)                                                              # the grantee works from the file alone, without the master key
        self.assertEqual(set(j2.grantee_open(gid, self.box)), set(got))

    def test_scopes_by_tag_time_and_everything(self):
        r = self.r
        g_tag = r.j.grant(self.sign.public, self.box.public, "full", {"kind": "tags", "tags": ["food"]}, r.owner)
        self.assertEqual(set(r.j.grantee_open(g_tag, self.box)), {self.e["recipe"]["sha256"]})
        lo, hi = self.e["guitar"]["at"], self.e["house"]["at"]
        g_time = r.j.grant(self.sign.public, self.box.public, "full", {"kind": "time", "from": lo, "to": hi}, r.owner)
        self.assertEqual(set(r.j.grantee_open(g_time, self.box)), {self.e["guitar"]["sha256"], self.e["house"]["sha256"]})
        g_all = r.j.grant(self.sign.public, self.box.public, "full", {"kind": "all"}, r.owner)
        self.assertEqual(len(r.j.grantee_open(g_all, self.box)), len(r.j.entries))
        for bad in ({}, {"kind": "everything"}, {"kind": "tags", "tags": []}, {"kind": "sessions", "sessions": "wishes"}, {"kind": "time", "from": 5, "to": 1}, {"kind": "time", "from": True, "to": 5}, None):
            with self.assertRaises(JournalRefused):
                r.j.grant(self.sign.public, self.box.public, "full", bad, r.owner)

    def test_new_entries_reach_a_full_grantee_only_when_the_owner_shares_them(self):
        r = self.r
        gid = r.j.grant(self.sign.public, self.box.public, "full", {"kind": "sessions", "sessions": ["wishes"]}, r.owner)
        new = r.j.add("owner", "The piano goes to Ben.", session="wishes")
        self.assertNotIn(new["sha256"], r.j.grantee_open(gid, self.box))
        self.assertEqual(r.j.share_new(gid, r.owner), 1)
        self.assertIn(new["sha256"], r.j.grantee_open(gid, self.box))
        self.assertEqual(r.j.share_new(gid, r.owner), 0)
        self.assertIn(new["sha256"], r.reopen(None).grantee_open(gid, self.box))

    def test_revocation_and_expiry_stop_access(self):
        r = self.r
        gid = r.j.grant(self.sign.public, self.box.public, "full", {"kind": "all"}, r.owner, expires_at=T0 + 10_000)
        r.j.grantee_open(gid, self.box)
        r.now["t"] = T0 + 10_001
        with self.assertRaises(JournalRefused):
            r.j.grantee_open(gid, self.box)
        gid2 = r.j.grant(self.sign.public, self.box.public, "answers_only", {"kind": "all"}, r.owner)
        r.j.ask(self.sign.public, "Who gets the guitar?", relevance=lambda q, u: 1.0 if "guitar" in u else 0)
        r.j.revoke(gid2, r.owner)
        with self.assertRaises(JournalRefused):
            r.j.ask(self.sign.public, "Who gets the guitar?")
        with self.assertRaises(JournalRefused):
            r.j.revoke(gid2, r.owner)
        for bad in (True, 5, T0 - 5):
            with self.assertRaises(JournalRefused):
                r.j.grant(self.sign.public, self.box.public, "full", {"kind": "all"}, r.owner, expires_at=bad)

    def test_an_answers_only_grant_carries_no_keys(self):
        r = self.r
        gid = r.j.grant(self.sign.public, self.box.public, "answers_only", {"kind": "tags", "tags": ["family"]}, r.owner)
        rec = [x for x in r.j.records if x["type"] == "grant"][-1]
        self.assertNotIn("grant_key_wrap", rec)
        self.assertNotIn("entries", rec)
        with self.assertRaises(JournalRefused):
            r.j.grantee_open(gid, self.box)                                             # nothing to open: they only ask
        rel = lambda q, u: 1.0 if ("guitar" in u.lower() and "guitar" in q.lower()) else 0.0
        ans = r.j.ask(self.sign.public, "Who should have the guitar?", rel)
        self.assertTrue(ans["answerable"])
        self.assertTrue(all(s["entry"] in (self.e["guitar"]["sha256"],) for s in ans["segments"]))
        out = r.j.ask(self.sign.public, "What does the soup need? Plenty of salt?", lambda q, u: 1.0 if "soup" in u.lower() else 0)     # outside the 'family' scope
        self.assertFalse(out["answerable"])
        stranger = crypto.Signer()
        with self.assertRaises(JournalRefused):
            r.j.ask(stranger.public, "Who should have the guitar?", rel)

    def test_forged_or_altered_policy_records_are_ignored_and_counted(self):
        r = self.r
        gid = r.j.grant(self.sign.public, self.box.public, "answers_only", {"kind": "tags", "tags": ["family"]}, r.owner)
        # a grant record written straight into the file by someone with file access, with a bad signature
        body = {"grantee_sign": crypto.Signer().public.hex(), "grantee_box": crypto.KeyPair().public.hex(), "mode": "answers_only", "scope": {"kind": "all"}, "expires_at": None, "created": T0}
        evil_id = P._sha(crypto.canonical(body))[:32]
        r.j._write("grant", grant_id=evil_id, sig="00" * 64, **body)
        j2 = r.reopen(r.M)
        self.assertEqual((j2.rejected, evil_id in j2.grants, gid in j2.grants), (1, False, True))
        forged_revoke_target = r.j.grant(self.sign.public, self.box.public, "answers_only", {"kind": "all"}, r.owner)
        r.j._write("revoke", grant_id=forged_revoke_target, sig="11" * 64)
        self.assertNotIn(forged_revoke_target, r.reopen(r.M).revoked)
        self.assertEqual(r.reopen(r.M).rejected, 2)

    def test_only_the_unlocked_owner_can_grant(self):
        r = self.r
        with self.assertRaises(P.Locked):
            r.reopen(None).grant(self.sign.public, self.box.public, "full", {"kind": "all"}, r.owner)
        with self.assertRaises(JournalRefused):
            r.j.grant(b"short", self.box.public, "full", {"kind": "all"}, r.owner)
        with self.assertRaises(JournalRefused):
            r.j.grant(self.sign.public, self.box.public, "read_only", {"kind": "all"}, r.owner)


class GroundedAnswers(unittest.TestCase):
    def setUp(self):
        self.r = Rig()
        self.e = self.r.fill()
        self.rel = lambda q, u: G.lexical_relevance(q, u)

    def test_the_owner_gets_quotations_and_nothing_else(self):
        r = self.r
        ans = r.j.ask(r.owner.public, "Who should have the guitar, my sister Anna?")
        self.assertTrue(ans["answerable"])
        self.assertEqual([s["text"] for s in ans["segments"]], ["I want my sister Anna to have my guitar."])
        text = G.render(ans)
        self.assertIn('"I want my sister Anna to have my guitar."', text)
        self.assertEqual(text.count("\n"), 0)
        self.assertTrue(r.j.verify_answer("Who should have the guitar, my sister Anna?", ans))

    def test_pieces_from_several_entries_are_joined_in_the_order_they_were_written(self):
        r = self.r
        q = "What about Anna, the guitar and the money?"
        ans = r.j.ask(r.owner.public, q)
        self.assertTrue(ans["answerable"], ans)
        entries = [s["entry"] for s in ans["segments"]]
        self.assertEqual(entries, sorted(entries, key=lambda sha: r.j.entries[sha]["i"]))
        self.assertGreaterEqual(len(set(entries)), 2)
        self.assertTrue(r.j.verify_answer(q, ans))

    def test_no_answer_if_the_journal_does_not_say_it(self):
        r = self.r
        for q in ("What is my favourite colour?", "Where was I born?", "!!!", "the a of"):
            a = r.j.ask(r.owner.public, q)
            self.assertFalse(a["answerable"], q)
            self.assertEqual(a["segments"], [])
        part = r.j.ask(r.owner.public, "Who gets the guitar and who gets the motorcycle?", min_score=0.3)
        self.assertFalse(part["answerable"])                                              # half a question is not answered
        self.assertIn("only part", part["reason"])
        self.assertFalse(r.j.ask(r.owner.public, "Who gets the guitar and who gets the motorcycle?")["answerable"])
        self.assertEqual(G.render(part), part["reason"])

    def test_only_the_owners_own_unredacted_words_ever_answer(self):
        r = self.r
        a = r.j.ask(r.owner.public, "A different guitar for the band?")
        self.assertFalse(a["answerable"])                                                 # that was the model speaking, not the owner (its words match the question fully)
        r.j.add("owner", "My key for the vault is sk-" + "aB3dE5gH" * 4 + " and the vault stays shut.")
        self.assertFalse(r.j.ask(r.owner.public, "Where is the vault key?")["answerable"])
        r.j.add("observer", "The owner wants the garden sold to the neighbours.")
        self.assertFalse(r.j.ask(r.owner.public, "The garden sold to the neighbours?")["answerable"])

    def test_wishes_are_not_returned_by_ordinary_questions(self):
        r = self.r
        LR.wish(r.j, r.owner, "boat", "property", "My sailboat", "Ben", "He loves the sea")
        a = r.j.ask(r.owner.public, "Ben sailboat?")
        self.assertFalse(a["answerable"])

    def test_video_answers_point_at_the_original_recording_and_never_cut_inside_a_segment(self):
        r = self.r
        sha = "cd" * 32
        media = {"type": "video", "sha256": sha, "bytes": 5000, "segments": [{"start_ms": 0, "end_ms": 4000, "text": "The old truck goes to my cousin Rafael."}, {"start_ms": 4000, "end_ms": 9000, "text": "He promised to keep it running."}]}
        r.j.add("owner", "", session="video", media=media)
        ans = r.j.ask(r.owner.public, "Where does the truck go, my cousin Rafael?")
        self.assertTrue(ans["answerable"])
        seg = ans["segments"][0]
        self.assertEqual(seg["media"], {"sha256": sha, "start_ms": 0, "end_ms": 4000})
        self.assertEqual(seg["text"], "The old truck goes to my cousin Rafael.")
        self.assertIn("recording cdcdcdcdcdcd.. 0-4000 ms", G.render(ans))
        self.assertTrue(r.j.verify_answer("Where does the truck go, my cousin Rafael?", ans))
        bad = copy.deepcopy(ans)
        bad["segments"][0]["media"]["end_ms"] = 2000                                      # trimming the clip to a different cut
        self.assertFalse(r.j.verify_answer("Where does the truck go, my cousin Rafael?", bad))

    def test_every_alteration_of_an_answer_is_caught_by_verification(self):
        r = self.r
        q = "What about Anna, the guitar and the money?"
        kw = {}
        ans = r.j.ask(r.owner.public, q, **kw)
        self.assertTrue(r.j.verify_answer(q, ans, **kw))
        e = ans["segments"][0]["entry"]
        full = r.j.read(e)["text"]
        s0 = ans["segments"][0]
        edits = {
            "text changed": lambda a: a["segments"][0].update(text=s0["text"].replace("sister", "brother")),
            "part of a sentence only": lambda a: a["segments"][0].update(text=s0["text"][:-1], end=s0["end"] - 1),
            "offsets moved": lambda a: a["segments"][0].update(start=s0["start"] + 1),
            "another entry named": lambda a: a["segments"][0].update(entry=self.e["recipe"]["sha256"]),
            "unknown entry": lambda a: a["segments"][0].update(entry="00" * 32),
            "a model entry spliced in": lambda a: a["segments"].append({"entry": self.e["model"]["sha256"], "start": 0, "end": 25, "text": "You might consider a different guitar for the band.", "at": self.e["model"]["at"], "score": 1.0, "media": None}),
            "order reversed": lambda a: a["segments"].reverse(),
            "a unit repeated": lambda a: a["segments"].append(copy.deepcopy(a["segments"][-1])),
            "wrong time": lambda a: a["segments"][0].update(at=1),
            "no segments": lambda a: a.update(segments=[]),
            "not answerable": lambda a: a.update(answerable=False),
            "different terms": lambda a: a.update(question_terms=["anything"]),
        }
        self.assertGreaterEqual(len(full), len(s0["text"]))
        for name, edit in edits.items():
            bad = copy.deepcopy(ans)
            edit(bad)
            self.assertFalse(r.j.verify_answer(q, bad, **kw), name)
        for junk in (None, {}, "answer", []):
            self.assertFalse(r.j.verify_answer(q, junk, **kw))
        self.assertFalse(r.j.verify_answer(q, ans, min_score=0.99, coverage_min=0.7))      # a stricter reader finds a unit too weak

    def test_a_weak_unit_is_not_let_in_even_if_it_would_complete_the_coverage(self):
        r = Rig()
        r.j.add("owner", "Anna and Ben get the guitar.")
        r.tick()
        r.j.add("owner", "The piano is old.")
        a = r.j.ask(r.owner.public, "guitar anna ben piano")
        self.assertFalse(a["answerable"])                                                 # 'piano' alone scores 0.25: below the bar, so it cannot top up the coverage

    def test_pieces_are_shown_in_written_order_not_in_score_order(self):
        r = Rig()
        r.j.add("owner", "The guitar is for Anna.")
        r.tick()
        r.j.add("owner", "Anna and Ben share the house money.")
        a = r.j.ask(r.owner.public, "guitar anna money house", min_score=0.4)
        self.assertTrue(a["answerable"], a)
        self.assertEqual([x["text"] for x in a["segments"]], ["The guitar is for Anna.", "Anna and Ben share the house money."])
        self.assertTrue(a["segments"][1]["score"] > a["segments"][0]["score"])             # the later piece scored higher and still comes second

    def test_a_unit_that_adds_nothing_new_is_left_out(self):
        r = Rig()
        r.j.add("owner", "Anna and Ben get the guitar.")
        r.tick()
        r.j.add("owner", "Anna plays the guitar.")
        a = r.j.ask(r.owner.public, "guitar anna ben")
        self.assertTrue(a["answerable"])
        self.assertEqual([x["text"] for x in a["segments"]], ["Anna and Ben get the guitar."])

    def test_a_better_matcher_can_be_supplied_and_a_bad_one_is_refused(self):
        r = self.r
        a = r.j.ask(r.owner.public, "Who is to inherit the guitar?", relevance=lambda q, u: 1.0 if "guitar" in u else 0.0, coverage_min=0.3)
        self.assertTrue(a["answerable"])
        for bad in (lambda q, u: "high", lambda q, u: float("nan"), lambda q, u: True, lambda q, u: None):
            with self.assertRaises(G.GroundedRefused):
                r.j.ask(r.owner.public, "Who gets the guitar?", relevance=bad)
        for kw in ({"min_score": 0}, {"min_score": 2}, {"coverage_min": True}, {"max_units": 0}, {"max_units": True}):
            with self.assertRaises(G.GroundedRefused):
                r.j.ask(r.owner.public, "Who gets the guitar?", **kw)
        for q in ("", "   ", None, "x" * 1001):
            with self.assertRaises(G.GroundedRefused):
                r.j.ask(r.owner.public, q)

    def test_every_ask_is_recorded_without_the_question_text_and_a_chain_failure_blocks_the_answer(self):
        r = self.r
        r.j.ask(r.owner.public, "Who should have the guitar, my sister Anna?")
        ev = [e["payload"] for e in r.dag.content.entries() if e["kind"] == "JOURNAL_ACCESS"]
        self.assertEqual(len(ev), 1)
        self.assertNotIn("guitar", json.dumps(ev))
        self.assertEqual((ev[0]["as"], ev[0]["answerable"]), ("owner", True))
        real = r.dag.record

        def failing(kind, payload, parents=None):
            raise DagError("disk full")
        r.dag.record = failing
        with self.assertRaises(JournalRefused):
            r.j.ask(r.owner.public, "Who should have the guitar, my sister Anna?")
        r.dag.record = real

    def test_units_are_whole_sentences_with_exact_offsets(self):
        text = "First thing. Second thing! Is this third? Fourth thing without a stop"
        units = G.split_units(text)
        self.assertEqual([u[2] for u in units], ["First thing.", "Second thing!", "Is this third?", "Fourth thing without a stop"])
        for s, e, sent in units:
            self.assertEqual(text[s:e], sent)
        self.assertEqual(G.split_units("   "), [])


class Legacy(unittest.TestCase):
    def setUp(self):
        self.r = Rig()
        self.e = self.r.fill()
        r = self.r
        self.ex = {n: (crypto.Signer(), crypto.KeyPair()) for n in ("lawyer", "sister", "friend")}
        self.anna_s, self.anna_b = r.person()
        self.ben_s, self.ben_b = r.person()
        self.cat_s, self.cat_b = r.person()
        self.executors = {n: {"sign": s.public.hex(), "box": b.public.hex()} for n, (s, b) in self.ex.items()}
        self.bens = [{"name": "anna", "sign": self.anna_s.public.hex(), "box": self.anna_b.public.hex(), "mode": "full", "scope": {"kind": "tags", "tags": ["family"]}},
                     {"name": "ben", "sign": self.ben_s.public.hex(), "box": self.ben_b.public.hex(), "mode": "answers_only", "scope": {"kind": "sessions", "sessions": ["wishes"]}}]
        self.rel = lambda q, u: G.lexical_relevance(q, u)

    def set(self, **kw):
        args = dict(executors=self.executors, threshold=2, cooling_days=14, beneficiaries=self.bens, signer=self.r.owner)
        args.update(kw)
        return self.r.j.set_legacy(**args)

    def declare(self, who=("lawyer", "sister"), evidence="ee" * 32, j=None):
        j = j or self.r.j
        body = j.prepare_death(evidence)
        sigs = {n: self.ex[n][0].sign("death", {"death": body}) for n in who}
        return body, sigs, j.declare_death(body, sigs)

    def shares(self, j, who=("lawyer", "sister")):
        out = {}
        for n in who:
            sh = self.ex[n][1].unwrap(bytes.fromhex(j.legacy["shares"][n]))
            out[n] = sh
        return out

    def test_nothing_changes_while_the_owner_lives_and_policy_records_are_valid(self):
        r = self.r
        v = self.set()
        self.assertEqual((v, r.j.status()), (1, "living"))
        with self.assertRaises(JournalRefused):
            r.j.ask(self.anna_s.public, "Who gets the guitar?")                            # a beneficiary has nothing in life
        with self.assertRaises(JournalRefused):
            r.j.release(self.shares(r.j))
        self.assertEqual(self.set(), 2)
        self.assertEqual(r.reopen(r.M).legacy["body"]["version"], 2)

    def test_the_policy_is_validated(self):
        for kw in ({"executors": {"only": next(iter(self.executors.values()))}}, {"threshold": 1}, {"threshold": 4}, {"threshold": True}, {"cooling_days": 0}, {"cooling_days": 400},
                   {"beneficiaries": [self.bens[0], self.bens[0]]}, {"beneficiaries": [dict(self.bens[0], mode="read")]}, {"beneficiaries": [dict(self.bens[0], scope={"kind": "?"})]}):
            with self.assertRaises(JournalRefused, msg=str(kw)[:60]):
                self.set(**kw)
        with self.assertRaises(P.Locked):
            self.r.reopen(None).set_legacy(self.executors, 2, 14, self.bens, self.r.owner)

    def test_a_death_needs_k_executors_signing_the_same_declaration(self):
        r = self.r
        self.set()
        body = r.j.prepare_death("ee" * 32)
        one = {"lawyer": self.ex["lawyer"][0].sign("death", {"death": body})}
        with self.assertRaises(JournalRefused):
            r.j.declare_death(body, one)
        forged = {"lawyer": self.ex["lawyer"][0].sign("death", {"death": body}), "sister": self.ex["friend"][0].sign("death", {"death": body})}
        with self.assertRaises(JournalRefused):
            r.j.declare_death(body, forged)                                              # a signature by someone else under an executor's name
        other = dict(body, evidence_sha256="ff" * 32)
        wrong_body = {n: self.ex[n][0].sign("death", {"death": other}) for n in ("lawyer", "sister")}
        with self.assertRaises(JournalRefused):
            r.j.declare_death(body, wrong_body)                                          # signed a different declaration
        stranger = {"lawyer": one["lawyer"], "mallory": crypto.Signer().sign("death", {"death": body})}
        with self.assertRaises(JournalRefused):
            r.j.declare_death(body, stranger)
        self.assertEqual(r.j.status(), "living")
        _, _, did = self.declare()
        self.assertEqual(r.j.status(), "death_declared_cooling")
        self.assertIn(did, r.j.deaths)
        with self.assertRaises(JournalRefused):
            r.j.prepare_death("short")

    def test_the_owner_can_cancel_during_the_cooling_off_and_not_after(self):
        r = self.r
        self.set()
        _, _, did = self.declare()
        r.tick(5 * DAY)
        r.j.alive(did, r.owner)
        self.assertEqual(r.j.status(), "living")
        _, _, did2 = self.declare(who=("sister", "friend"))
        r.now["t"] += 15 * DAY
        self.assertEqual(r.j.status(), "legacy_effective")
        with self.assertRaises(JournalRefused):
            r.j.alive(did2, r.owner)
        with self.assertRaises(JournalRefused):
            r.j.alive("nosuch", r.owner)

    def test_release_needs_an_effective_declaration_and_enough_correct_shares(self):
        r = self.r
        self.set()
        self.declare()
        with self.assertRaises(JournalRefused):
            r.j.release(self.shares(r.j))                                                # still cooling off
        r.now["t"] += 15 * DAY
        sh = self.shares(r.j)
        with self.assertRaises(JournalRefused):
            r.j.release({"lawyer": sh["lawyer"]})                                        # one share
        with self.assertRaises(JournalRefused):
            r.j.release({"lawyer": sh["lawyer"], "sister": bytes([sh["sister"][0]]) + bytes(32)})        # a wrong share
        with self.assertRaises(JournalRefused):
            r.j.release({"lawyer": sh["lawyer"], "sister": sh["lawyer"]})                # the same share twice
        self.assertTrue(r.j.release(sh))
        self.assertTrue(any(x["type"] == "released" for x in r.j.records))

    def test_after_release_each_beneficiary_gets_exactly_what_the_policy_says_and_no_one_else_anything(self):
        r = self.r
        self.set()
        self.declare()
        r.now["t"] += 15 * DAY
        dead = r.reopen(None)                                                            # the owner is gone: no master key
        with self.assertRaises(JournalRefused):
            dead.ask(self.ben_s.public, "Who gets the guitar?")                          # not released yet
        dead.release(self.shares(dead))
        rel = lambda q, u: 1.0 if ("guitar" in q.lower() and "guitar" in u.lower()) else 0.0
        ben = dead.ask(self.ben_s.public, "Who gets the guitar?", rel)                    # answers-only beneficiary, scope: the 'wishes' session
        self.assertTrue(ben["answerable"])
        self.assertTrue(all(dead.entries[s["entry"]]["session"] == "wishes" for s in ben["segments"]))
        out = dead.ask(self.ben_s.public, "Does the soup need salt?", lambda q, u: 1.0 if "soup" in u.lower() else 0.0)
        self.assertFalse(out["answerable"])
        anna = dead.beneficiary_open("anna", self.anna_b)                                # full beneficiary, scope: the 'family' tag
        self.assertEqual(set(anna), {self.e["guitar"]["sha256"], self.e["house"]["sha256"]})
        self.assertNotIn(self.e["recipe"]["sha256"], anna)
        for stranger in (self.cat_s, crypto.Signer()):
            with self.assertRaises(JournalRefused):
                dead.ask(stranger.public, "Who gets the guitar?", rel)
        with self.assertRaises(JournalRefused):
            dead.beneficiary_open("anna", self.cat_b)                                    # another person's box key
        with self.assertRaises(JournalRefused):
            dead.beneficiary_open("ben", self.ben_b)                                     # an answers-only beneficiary has no bundle
        with self.assertRaises(P.Locked):
            dead.ask(r.owner.public, "Who gets the guitar?", rel)                        # the master key died with the owner

    def test_executors_cannot_read_what_they_guard(self):
        r = self.r
        self.set()
        self.declare()
        r.now["t"] += 15 * DAY
        dead = r.reopen(None)
        dead.release(self.shares(dead))
        rel = lambda q, u: 1.0
        for name in self.ex:
            with self.assertRaises(JournalRefused):
                dead.ask(self.ex[name][0].public, "Who gets the guitar?", rel)            # an executor is not a beneficiary
            with self.assertRaises(JournalRefused):
                dead.beneficiary_open("anna", self.ex[name][1])                          # nor can their box key open Anna's bundle

    def test_two_executors_short_of_the_threshold_can_do_nothing_but_the_threshold_can(self):
        r = self.r
        self.set(threshold=3)
        body = r.j.prepare_death("ee" * 32)
        two = {n: self.ex[n][0].sign("death", {"death": body}) for n in ("lawyer", "sister")}
        with self.assertRaises(JournalRefused):
            r.j.declare_death(body, two)
        three = {n: self.ex[n][0].sign("death", {"death": body}) for n in self.ex}
        r.j.declare_death(body, three)

    def test_a_restart_remembers_the_death_but_asks_for_the_shares_again(self):
        r = self.r
        self.set()
        self.declare()
        r.now["t"] += 15 * DAY
        r.j.release(self.shares(r.j))
        again = r.reopen(None)
        self.assertEqual(again.status(), "legacy_effective")
        rel = lambda q, u: 1.0 if "guitar" in u.lower() else 0.0
        with self.assertRaises(JournalRefused):
            again.ask(self.ben_s.public, "Who gets the guitar?", rel)                    # the service key is not stored anywhere
        again.release(self.shares(again))
        self.assertTrue(again.ask(self.ben_s.public, "Who gets the guitar?", rel)["answerable"])
        self.assertEqual(sum(1 for x in again.records if x["type"] == "released"), 1)

    def test_forged_legacy_and_death_records_have_no_effect(self):
        r = self.r
        self.set()
        before = len(r.j.records)
        legacy_rec = copy.deepcopy([x for x in r.j.records if x["type"] == "legacy"][-1])
        for k in ("i", "at", "prev", "sha256", "type"):
            legacy_rec.pop(k)
        evil = copy.deepcopy(legacy_rec)
        evil["body"]["beneficiaries"] = [{"name": "mallory", "sign": crypto.Signer().public.hex(), "box": crypto.KeyPair().public.hex(), "mode": "answers_only", "scope": {"kind": "all"}}]
        evil["body"]["version"] = 2
        r.j._write("legacy", **evil)                                                    # a record with the owner's old signature over different content
        body = r.j.prepare_death("ee" * 32)
        r.j._write("death", body=body, sigs={"lawyer": "00" * 64, "sister": "11" * 64})
        j2 = r.reopen(r.M)
        self.assertEqual(j2.legacy["body"]["version"], 1)
        self.assertEqual(j2.deaths, {})
        self.assertEqual(j2.rejected, 2)
        self.assertEqual(j2.status(), "living")
        self.assertGreater(len(j2.records), before)

    def test_a_validly_signed_legacy_that_skips_a_version_and_a_late_cancellation_are_ignored(self):
        r = self.r
        self.set()
        rec = {k: v for k, v in [x for x in r.j.records if x["type"] == "legacy"][-1].items() if k not in ("i", "at", "prev", "sha256", "type")}
        body5 = dict(rec["body"], version=5)
        signed = {"body": body5, "check": rec["check"], "sealed_service": rec["sealed_service"], "bundles_sha": P._sha(crypto.canonical(rec["bundles"])), "shares_sha": P._sha(crypto.canonical(rec["shares"]))}
        r.j._write("legacy", **dict(rec, body=body5, sig=r.owner.sign("legacy", signed)))        # the owner's real signature, but version 5 follows version 1
        self.assertEqual(r.reopen(r.M).legacy["body"]["version"], 1)
        self.assertEqual(r.reopen(r.M).rejected, 1)
        _, _, did = self.declare()
        r.now["t"] += 15 * DAY
        r.j._write("alive", death_id=did, sig=r.owner.sign("alive", {"death_id": did}))             # signed by the owner, but after the cooling-off ended
        j2 = r.reopen(r.M)
        self.assertEqual((j2.status(), j2.rejected), ("legacy_effective", 2))

    def test_a_declaration_for_an_older_policy_version_is_refused(self):
        r = self.r
        self.set()
        old_body = r.j.prepare_death("ee" * 32)
        self.set()
        sigs = {n: self.ex[n][0].sign("death", {"death": old_body}) for n in ("lawyer", "sister")}
        with self.assertRaises(JournalRefused):
            r.j.declare_death(old_body, sigs)


class LastRites(unittest.TestCase):
    def setUp(self):
        self.r = Rig()

    def test_wishes_are_signed_versioned_and_withdrawable(self):
        r = self.r
        w1 = LR.wish(r.j, r.owner, "guitar", "property", "My Martin guitar", "Anna", "She learned on it", assurance=4)
        r.tick()
        LR.wish(r.j, r.owner, "boat", "property", "The sailboat", "Ben")
        r.tick()
        w3 = LR.wish(r.j, r.owner, "guitar", "property", "My Martin guitar", "Ben", "I changed my mind", assurance=4)
        cur = {p["wish_id"]: p for _, p in LR.current_wishes(r.j)}
        self.assertEqual((cur["guitar"]["recipient"], cur["guitar"]["supersedes"]), ("Ben", w1["sha256"]))
        self.assertIn(w1["sha256"], r.j.wish_records)                                     # the history stays in the chain
        LR.wish(r.j, r.owner, "boat", "property", "The sailboat", "Ben", revoked=True)
        self.assertEqual([p["wish_id"] for _, p in LR.current_wishes(r.j)], ["guitar"])
        for bad in (dict(wish_id="Bad Id", kind="property", item="x", recipient="y"), dict(wish_id="ok1", kind="spell", item="x", recipient="y"), dict(wish_id="ok1", kind="property", item="", recipient="y"),
                    dict(wish_id="ok1", kind="property", item="x" * 501, recipient="y"), dict(wish_id="ok1", kind="property", item="x", recipient="y", assurance=5),
                    dict(wish_id="ok1", kind="property", item="x", recipient="y", assurance=True)):
            with self.assertRaises(JournalRefused):
                LR.wish(r.j, r.owner, **bad)
        with self.assertRaises(JournalRefused):
            LR.wish(r.j, crypto.Signer(), "x1", "property", "a", "b")                      # not the owner's key
        self.assertEqual(w3["tags"], ["last_rites"])
        self.assertEqual(r.reopen(r.M).wish_records.keys(), r.j.wish_records.keys())

    def test_a_forged_wish_record_does_not_count(self):
        r = self.r
        sha = crypto.canonical({"wish_id": "fake"})
        r.j.add("owner", "ordinary entry")
        rec = r.j._make_entry("owner", json.dumps({"wish_id": "fake", "kind": "property", "item": "everything", "recipient": "mallory", "note": "", "revoked": False, "supersedes": None}),
                              "last_rites", "wish", None, ["last_rites"], None, {"payload_sha256": "00" * 32, "assurance": 4, "osig": "00" * 64})
        j2 = r.reopen(r.M)
        self.assertNotIn(rec["sha256"], j2.wish_records)
        self.assertEqual(LR.current_wishes(j2), [])

    def test_witnesses_count_only_with_valid_signatures(self):
        r = self.r
        w = LR.wish(r.j, r.owner, "house", "property", "The house", "Anna and Ben")
        w1, w2 = crypto.Signer(), crypto.Signer()
        LR.witness(r.j, w["sha256"], w1)
        pkt = LR.statement_of_wishes(r.j, r.owner)
        self.assertEqual((pkt["wishes"][0]["status"], len(pkt["wishes"][0]["witnesses"])), ("owner_signed", 1))
        LR.witness(r.j, w["sha256"], w2)
        pkt = LR.statement_of_wishes(r.j, r.owner)
        self.assertEqual(pkt["wishes"][0]["status"], "witnessed")
        r.j._write("witness", wish=w["sha256"], witness_sign=crypto.Signer().public.hex(), sig="00" * 64)
        self.assertEqual(r.reopen(r.M).rejected, 1)
        with self.assertRaises(JournalRefused):
            LR.witness(r.j, "00" * 32, w1)

    def test_the_statement_verifies_from_the_packet_alone_and_catches_every_change(self):
        r = self.r
        LR.wish(r.j, r.owner, "guitar", "property", "My Martin guitar", "Anna", "She learned on it", assurance=4)
        w = LR.wish(r.j, r.owner, "house", "property", "The house", "Anna and Ben", assurance=3)
        LR.witness(r.j, w["sha256"], crypto.Signer())
        LR.witness(r.j, w["sha256"], crypto.Signer())
        r.tick()
        pkt = LR.statement_of_wishes(r.j, r.owner)
        pkt = json.loads(json.dumps(pkt))
        self.assertEqual(LR.verify_statement(pkt), [])
        self.assertIn("NOT a will", pkt["notice"])
        self.assertEqual({x["status"] for x in pkt["wishes"]}, {"owner_signed", "witnessed"})
        edits = {
            "text": lambda p: p["wishes"][0].update(payload_text=p["wishes"][0]["payload_text"].replace("Anna", "Mallory")),
            "assurance": lambda p: p["wishes"][0].update(assurance=0),
            "owner sig": lambda p: p["wishes"][0].update(owner_sig="00" * 64),
            "tags": lambda p: p["wishes"][0].update(tags=["last_rites", "extra"]),
            "root": lambda p: p.update(journal_root="00" * 32),
            "proof": lambda p: p["wishes"][0]["proof"]["path"].pop(),
            "record": lambda p: p["wishes"][0].update(record_sha256="00" * 32),
            "witness sig": lambda p: p["wishes"][1]["witnesses"][0].update(sig="00" * 64),
            "status": lambda p: p["wishes"][0].update(status="witnessed"),
            "notice": lambda p: p.update(notice="This is a will."),
            "export sig": lambda p: p.update(export_sig="00" * 64),
            "owner key": lambda p: p.update(owner_sign=crypto.Signer().public.hex()),
            "wish id": lambda p: p["wishes"][0].update(wish_id="other"),
            "dropped field": lambda p: p.pop("wishes"),
        }
        for name, edit in edits.items():
            bad = copy.deepcopy(pkt)
            edit(bad)
            self.assertTrue(LR.verify_statement(bad), name)                                # caught (at least by the packet's own signature)
            if name not in ("export sig", "owner key", "dropped field"):
                body = {k: v for k, v in bad.items() if k != "export_sig"}
                bad["export_sig"] = self.r.owner.sign("statement", body)                    # a forger who holds the owner's key re-signs the packet: the inner checks must still catch the change
                self.assertTrue(LR.verify_statement(bad), name + " (re-signed)")
        for junk in (None, {}, "x", []):
            self.assertTrue(LR.verify_statement(junk))

    def test_only_the_unlocked_owner_exports_and_revoked_or_replaced_wishes_are_left_out(self):
        r = self.r
        LR.wish(r.j, r.owner, "a-wish", "message", "Tell Ben I was proud of him", "Ben")
        LR.wish(r.j, r.owner, "a-wish", "message", "Tell Ben I was proud of him", "Ben", revoked=True)
        LR.wish(r.j, r.owner, "other", "funeral", "A small gathering by the lake", "")
        pkt = LR.statement_of_wishes(r.j, r.owner)
        self.assertEqual([w["wish_id"] for w in pkt["wishes"]], ["other"])
        with self.assertRaises(JournalRefused):
            LR.statement_of_wishes(r.j, crypto.Signer())
        with self.assertRaises(P.Locked):
            LR.statement_of_wishes(r.reopen(None), r.owner)

    def test_a_beneficiary_scoped_to_last_rites_gets_only_the_wishes(self):
        r = self.r
        r.j.add("owner", "A private thought nobody should read.", session="private")
        w = LR.wish(r.j, r.owner, "guitar", "property", "My Martin guitar", "Anna")
        ex = {n: (crypto.Signer(), crypto.KeyPair()) for n in ("a", "b")}
        anna_s, anna_b = crypto.Signer(), crypto.KeyPair()
        r.j.set_legacy({n: {"sign": s.public.hex(), "box": b.public.hex()} for n, (s, b) in ex.items()}, 2, 7,
                       [{"name": "anna", "sign": anna_s.public.hex(), "box": anna_b.public.hex(), "mode": "full", "scope": {"kind": "tags", "tags": ["last_rites"]}}], r.owner)
        body = r.j.prepare_death("ee" * 32)
        r.j.declare_death(body, {n: ex[n][0].sign("death", {"death": body}) for n in ex})
        r.now["t"] += 8 * DAY
        dead = r.reopen(None)
        dead.release({n: ex[n][1].unwrap(bytes.fromhex(dead.legacy["shares"][n])) for n in ex})
        got = dead.beneficiary_open("anna", anna_b)
        self.assertEqual(set(got), {w["sha256"]})
        self.assertIn("Martin guitar", got[w["sha256"]]["text"])


if __name__ == "__main__":
    unittest.main()
