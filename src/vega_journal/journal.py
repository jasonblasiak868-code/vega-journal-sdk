"""journal.py - the Q and A journal: a verbatim, append-only, hash-chained record of what was asked and answered, and a map of where each idea first appeared.

THE STORE is one JSON-lines file. Every line is a RECORD with a position, a time, a type, its content and the hash of the record before it; its own hash covers all of that, so editing, deleting or
reordering any line breaks every hash after it and verify() says where. Record types:
  entry   a line of conversation: speaker (owner, model, observer, system), session, text, kind (note, question, answer; an answer names the question it answers)
  idea    a named idea with its FIRST anchor: an exact quotation from an entry (start and end offsets and the hash of the quoted text) and its origin (who said it)
  anchor  a later appearance of an idea (a refinement)
  edge    'this idea grew from that idea', recorded in an entry; cycles are refused
Text is kept VERBATIM, except that text holding a credential-shaped value is stored as a marker with the hash of the original (the journal must never become the place a key leaks from).
THE CHAIN gets a hash-only event per record (JOURNAL_RECORD), written BEFORE the line is appended; verify() lists any record on one side and not the other.
ORIGIN MATTERS: an idea anchored in an OBSERVER or MODEL entry is credited to that origin, never to the owner; the conception receipt says which, and refuses to call a model's suggestion the owner's.
RECEIPTS: conception_receipt(idea) gives the earliest anchor, its record hash, the Merkle root of the whole journal and an inclusion proof, so a third party can check the entry was in the journal at that point.
HONEST LIMITS: the times are the machine's clock when the record was written (anchor the root externally, for example with a public timestamp, if the date must be provable to someone who does not trust the
machine). A journal proves WHAT was recorded and WHEN it was recorded; conception is not priority, and who invented an idea first is for a filing and the law, not for this file."""
import functools
import hashlib
import json
import os
import re
import threading
import time

from vega_custody.dag.dag import DagError, _FileLock, contains_credential
from vega_journal import merkle

SPEAKERS = ("owner", "model", "observer", "system")
KINDS = ("note", "question", "answer")
MAX_TEXT = 200_000
NAME = re.compile(r"^[a-z0-9][a-z0-9 _.-]{1,60}$")
MARK = "[REDACTED: credential-shaped value; original hash kept]"
ZERO = "0" * 64


class JournalRefused(ValueError):
    pass


_GUARD, _LOCKS = threading.Lock(), {}


def _path_lock(path):
    """One re-entrant lock per journal file in this process, shared by every Journal object on it."""
    key = os.path.abspath(os.fspath(path))
    with _GUARD:
        return _LOCKS.setdefault(key, threading.RLock())


def atomic(fn):
    """A check and the write that follows it run as one step ('does that idea exist?' then record it): no other writer gets in between."""
    @functools.wraps(fn)
    def inner(self, *a, **k):
        with self._lock:
            return fn(self, *a, **k)
    return inner


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _hash(rec) -> str:
    return hashlib.sha256(b"VEGA-JOURNAL-1|" + _canon({k: v for k, v in rec.items() if k != "sha256"})).hexdigest()


def _tokens(text):
    return re.findall(r"[^\W_]{2,}", text.casefold())


class Journal:
    def __init__(self, path, dag, clock=time.time):
        self.path, self.dag, self._clock = os.fspath(path), dag, clock
        self._lock = _path_lock(self.path)
        self._reset()
        if os.path.exists(self.path):
            self._load()

    def _reset(self):
        self.records, self.entries, self.ideas, self.edges = [], {}, {}, []
        self._index, self._df = {}, {}
        self._size = 0                                            # the size of the file this view was built from: a writer whose view is stale is refused

    def _index_text(self, rec) -> str:
        """The plain text of an entry for indexing and quoting. A private journal overrides this (and returns '' while it is locked)."""
        return rec["text"]

    def _apply_extra(self, rec):
        """Record types the base journal does not know (policies, grants...) are handled by a subclass."""

    # ---- loading and checking ---------------------------------------------------------------------------------------------
    def _load(self):
        with open(self.path, "r", encoding="utf-8", newline="\n") as fh:
            data = fh.read()
        if data and not data.endswith("\n"):
            raise JournalRefused("the journal ends in a half-written line: refusing to guess; restore or repair it by hand")
        prev = ZERO
        for n, line in enumerate(data.split("\n")[:-1]):
            try:
                rec = json.loads(line)
            except ValueError as exc:
                raise JournalRefused("line %d is not JSON" % (n + 1)) from exc
            if not isinstance(rec, dict) or rec.get("i") != n or rec.get("prev") != prev or rec.get("sha256") != _hash(rec):
                raise JournalRefused("the chain breaks at record %d: the journal was edited, reordered or cut" % n)
            self._apply(rec)
            prev = rec["sha256"]
        self._size = os.path.getsize(self.path)

    def _apply(self, rec):
        self.records.append(rec)
        t = rec["type"]
        if t == "entry":
            self.entries[rec["sha256"]] = rec
            for tok in set(_tokens(self._index_text(rec))):
                self._index.setdefault(tok, []).append(rec["sha256"])
        elif t == "idea":
            self.ideas[rec["name"].casefold()] = {"name": rec["name"], "anchors": [self._anchor_of(rec)], "parents": [], "created": rec["i"]}
        elif t == "anchor":
            self.ideas[rec["name"].casefold()]["anchors"].append(self._anchor_of(rec))
        elif t == "edge":
            self.ideas[rec["child"].casefold()]["parents"].append(rec["parent"].casefold())
            self.edges.append((rec["child"].casefold(), rec["parent"].casefold(), rec["entry"]))
        else:
            self._apply_extra(rec)

    def _anchor_of(self, rec):
        """An anchor is dated by WHEN THE WORDS WERE WRITTEN (the entry), not by when someone later pointed at them; the time the anchor itself was recorded is kept separately."""
        e = self.entries[rec["entry"]]
        return {"entry": rec["entry"], "start": rec["start"], "end": rec["end"], "quote_sha256": rec["quote_sha256"], "origin": rec["origin"], "i": e["i"], "at": e["at"],
                "recorded_i": rec["i"], "recorded_at": rec["at"]}

    @property
    def head(self) -> str:
        return self.records[-1]["sha256"] if self.records else ZERO

    def _write(self, rec_type, **fields) -> dict:
        # In this process every writer on this file takes the same lock; across processes the file lock does the same job. Inside it the writer checks that the file is still the
        # one its view was built from, so a record can never be given a position or a previous hash that someone else has already used (which would fork the file's hash chain).
        with self._lock, _FileLock(self.path):
            size_now = os.path.getsize(self.path) if os.path.exists(self.path) else 0
            if size_now != self._size:
                raise JournalRefused("the journal changed underneath this writer (another writer?): reopen it. Nothing was recorded.")
            now = int(self._clock())
            if self.records and now < self.records[-1]["at"]:
                raise JournalRefused("the clock went backwards: refusing to write a record dated before the last one")
            rec = {"i": len(self.records), "at": now, "type": rec_type, "prev": self.head}
            rec.update(fields)
            rec["sha256"] = _hash(rec)
            try:
                self.dag.record("JOURNAL_RECORD", {"type": rec_type, "position": rec["i"], "record_sha256": rec["sha256"]})
            except DagError as exc:
                raise JournalRefused("the chain could not be written: nothing was recorded: %s" % exc) from exc
            with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._size = os.path.getsize(self.path)
            self._apply(rec)
            return rec

    def _clone_empty(self):
        fresh = type(self).__new__(type(self))
        fresh.path, fresh.dag, fresh._clock = self.path, self.dag, self._clock
        fresh._lock = self._lock
        fresh._copy_config_from(self)
        fresh._reset()
        return fresh

    def _copy_config_from(self, other):
        pass

    def verify(self):
        """-> (ok, problems). Re-reads the file and re-checks every hash, and compares with the chain's JOURNAL_RECORD events."""
        problems = []
        try:
            fresh = self._clone_empty()
            fresh._load()
        except JournalRefused as exc:
            return False, [str(exc)]
        file_hashes = [r["sha256"] for r in fresh.records]
        chain_hashes = [e["payload"]["record_sha256"] for e in self.dag.content.entries() if e["kind"] == "JOURNAL_RECORD"]
        for h in file_hashes:
            if h not in chain_hashes:
                problems.append("record %s is in the file but not in the chain" % h[:12])
        for h in chain_hashes:
            if h not in file_hashes:
                problems.append("record %s is in the chain but not in the file" % h[:12])
        return not problems, problems

    # ---- entries -------------------------------------------------------------------------------------------------------------------
    @atomic
    def _entry(self, speaker, text, session, kind, answers=None):
        if speaker not in SPEAKERS or kind not in KINDS:
            raise JournalRefused("speaker is one of %s and kind one of %s" % (SPEAKERS, KINDS))
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT or "\x00" in text:
            raise JournalRefused("text is 1 to %d characters without NUL" % MAX_TEXT)
        if not isinstance(session, str) or not 1 <= len(session) <= 80 or not session.isprintable():
            raise JournalRefused("session is a short printable label")
        original = hashlib.sha256(text.encode("utf-8")).hexdigest()
        redacted = contains_credential(text)
        return self._write("entry", speaker=speaker, session=session, kind=kind, answers=answers, text=MARK if redacted else text, original_sha256=original, redacted=redacted)

    def add(self, speaker, text, session="default", kind="note") -> dict:
        if kind == "answer":
            raise JournalRefused("use answer() so the question it answers is named")
        return self._entry(speaker, text, session, kind)

    def question(self, speaker, text, session="default") -> dict:
        return self._entry(speaker, text, session, "question")

    def answer(self, question_id, speaker, text, session="default") -> dict:
        q = self.entries.get(question_id) if isinstance(question_id, str) else None
        if q is None or q["kind"] != "question":
            raise JournalRefused("an answer names the question it answers")
        return self._entry(speaker, text, session, "answer", answers=question_id)

    def get(self, entry_id) -> dict:
        e = self.entries.get(entry_id) if isinstance(entry_id, str) else None
        if e is None:
            raise JournalRefused("no such entry")
        return e

    def pairs(self):
        qs = {e["sha256"]: e for e in self.entries.values() if e["kind"] == "question"}
        return [(qs[a["answers"]], a) for a in sorted(self.entries.values(), key=lambda r: r["i"]) if a["kind"] == "answer"]

    def unanswered(self):
        done = {a["answers"] for a in self.entries.values() if a["kind"] == "answer"}
        return sorted((e for e in self.entries.values() if e["kind"] == "question" and e["sha256"] not in done), key=lambda r: r["i"])

    # ---- search ---------------------------------------------------------------------------------------------------------------------------
    def search(self, query: str, speaker: str = None, limit: int = 10):
        """Entries ranked by how many of the query's words they hold (rarer words count more). Words of 2+ letters; case-insensitive."""
        if not isinstance(query, str) or not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise JournalRefused("a query and a limit of 1 to 100")
        n = max(1, len(self.entries))
        scores = {}
        for tok in set(_tokens(query)):
            hits = self._index.get(tok, [])
            if not hits:
                continue
            w = 1.0 + (n / len(hits)) ** 0.5
            for h in hits:
                scores[h] = scores.get(h, 0.0) + w
        rows = [(s, self.entries[h]) for h, s in scores.items() if speaker is None or self.entries[h]["speaker"] == speaker]
        rows.sort(key=lambda x: (-x[0], x[1]["i"]))
        return [e for _, e in rows[:limit]]

    def first_use(self, term: str, speaker: str = None):
        """The earliest entry containing every word of the term, or None. 'None' means this journal holds no such entry, not that the idea never existed elsewhere."""
        toks = set(_tokens(term))
        if not toks:
            raise JournalRefused("the term has no words")
        cand = None
        for t in toks:
            ids = set(self._index.get(t, []))
            cand = ids if cand is None else cand & ids
        rows = sorted((self.entries[h] for h in (cand or [])), key=lambda r: r["i"])
        rows = [r for r in rows if speaker is None or r["speaker"] == speaker]
        return rows[0] if rows else None

    # ---- the thought genome -------------------------------------------------------------------------------------------------------------
    def _quote(self, entry_id, start, end):
        e = self.get(entry_id)
        if e["redacted"]:
            raise JournalRefused("an idea cannot be anchored in a redacted entry")
        text = self._index_text(e)
        if any(isinstance(v, bool) or not isinstance(v, int) for v in (start, end)) or not 0 <= start < end <= len(text):
            raise JournalRefused("start and end select a piece of the entry's text")
        return e, hashlib.sha256(text[start:end].encode("utf-8")).hexdigest()

    def _name(self, name):
        if not isinstance(name, str) or not NAME.fullmatch(name.strip().casefold()):
            raise JournalRefused("an idea name is 2 to 61 letters, digits, spaces, '.', '_' or '-'")
        return name.strip()

    @atomic
    def idea(self, name, entry_id, start, end) -> dict:
        name = self._name(name)
        if name.casefold() in self.ideas:
            raise JournalRefused("that idea already exists: add a later appearance with anchor()")
        e, q = self._quote(entry_id, start, end)
        return self._write("idea", name=name, entry=entry_id, start=start, end=end, quote_sha256=q, origin=e["speaker"])

    @atomic
    def anchor(self, name, entry_id, start, end) -> dict:
        name = self._name(name)
        if name.casefold() not in self.ideas:
            raise JournalRefused("no such idea")
        e, q = self._quote(entry_id, start, end)
        return self._write("anchor", name=self.ideas[name.casefold()]["name"], entry=entry_id, start=start, end=end, quote_sha256=q, origin=e["speaker"])

    @atomic
    def derive(self, child, parent, entry_id) -> dict:
        c, p = self._name(child).casefold(), self._name(parent).casefold()
        if c not in self.ideas or p not in self.ideas:
            raise JournalRefused("both ideas must exist")
        if c == p:
            raise JournalRefused("an idea cannot grow from itself")
        self.get(entry_id)
        stack, seen = [p], set()
        while stack:                                              # a cycle would make 'grew from' meaningless
            x = stack.pop()
            if x == c:
                raise JournalRefused("that edge would make the idea its own ancestor")
            if x not in seen:
                seen.add(x)
                stack.extend(self.ideas[x]["parents"])
        return self._write("edge", child=self.ideas[c]["name"], parent=self.ideas[p]["name"], entry=entry_id)

    def first_anchor(self, name, origin: str = None):
        a = self.ideas[self._name(name).casefold()]["anchors"] if self._name(name).casefold() in self.ideas else None
        if a is None:
            raise JournalRefused("no such idea")
        rows = sorted((x for x in a if origin is None or x["origin"] == origin), key=lambda x: x["i"])
        return rows[0] if rows else None

    def lineage(self, name):
        """The idea's ancestors, nearest first, each with its earliest anchor's time and origin."""
        key = self._name(name).casefold()
        if key not in self.ideas:
            raise JournalRefused("no such idea")
        out, seen, frontier = [], {key}, list(self.ideas[key]["parents"])
        while frontier:
            nxt = []
            for p in frontier:
                if p in seen:
                    continue
                seen.add(p)
                fa = min(self.ideas[p]["anchors"], key=lambda x: x["i"])
                out.append({"idea": self.ideas[p]["name"], "first_at": fa["at"], "origin": fa["origin"]})
                nxt.extend(self.ideas[p]["parents"])
            frontier = nxt
        return out

    # ---- proofs ---------------------------------------------------------------------------------------------------------------------------------
    def root(self) -> str:
        return merkle.root([r["sha256"] for r in self.records])

    def inclusion_proof(self, record_hash: str):
        hashes = [r["sha256"] for r in self.records]
        if record_hash not in hashes:
            raise JournalRefused("no such record")
        return {"index": hashes.index(record_hash), "size": len(hashes), "path": merkle.proof(hashes, hashes.index(record_hash))}

    def conception_receipt(self, name, origin: str = "owner") -> dict:
        """The earliest anchor of this idea by this ORIGIN, with the proof that its entry is in the journal. Refuses if the owner never said it (a model's suggestion is not the owner's conception)."""
        fa = self.first_anchor(name, origin)
        if fa is None:
            raise JournalRefused("no anchor for this idea has origin %r: the receipt will not credit it to someone who did not say it" % origin)
        entry = self.entries[fa["entry"]]
        return {"idea": self.ideas[self._name(name).casefold()]["name"], "origin": fa["origin"], "recorded_at": fa["at"], "entry_sha256": fa["entry"], "entry_position": entry["i"], "quote_start": fa["start"], "quote_end": fa["end"],
                "quote_sha256": fa["quote_sha256"], "journal_root": self.root(), "journal_size": len(self.records), "chain_head": self.head, "proof": self.inclusion_proof(fa["entry"])}


def verify_receipt(receipt: dict, quote_text: str = None) -> bool:
    """Checks the Merkle path, and (if the quotation is supplied) that it is exactly the quoted text. Never raises."""
    try:
        if not merkle.verify(receipt["journal_root"], receipt["entry_sha256"], [tuple(x) for x in receipt["proof"]["path"]]):
            return False
        return quote_text is None or hashlib.sha256(quote_text.encode("utf-8")).hexdigest() == receipt["quote_sha256"]
    except (KeyError, TypeError, ValueError):
        return False
