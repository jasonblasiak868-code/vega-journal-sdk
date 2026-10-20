"""grounded.py - answer a question FROM the journal and only from the journal: exact quotations, each one earned, nothing generated.

THE RULES (each is tested):
  1  An answer is made of WHOLE UNITS: a complete sentence of a text entry, or a complete transcript segment of a video or audio entry. Never a phrase cut from the middle, never a word from here and a word from there.
  2  Every unit must be RELEVANT ON ITS OWN: its score for this question (from the relevance function you supply) must reach min_score.
  3  Only the OWNER'S OWN words count: units spoken by the owner. Model, observer and system entries are never used to answer for the owner. Redacted entries are never used.
  4  Units may come from SEVERAL entries ('bits and pieces') if together they cover enough of what the question asks (coverage_min of its key terms) and each one adds to that coverage or is strongly relevant itself.
     A unit the relevance function scores 0.9 or more counts as covering the whole question by itself (a better matcher understands 'gets' and 'have' mean the same thing).
  5  Units stay in the order they were written (entry order, then position in the entry), each tied to its entry, its time and, for media, its start and end in the recording. Nothing is reordered to read better.
  6  NOTHING IS ADDED. The rendered answer is the quotations with their dates and nothing else. No paraphrase, no filler, no synthetic voice, no generated or edited video: a media segment is a pointer to the original recording's start and end.
  7  If the journal does not answer the question, the answer says exactly that. It never guesses, never offers 'the closest thing', never answers part of a different question.
verify_answer() re-checks an answer against the journal's own text: every quotation really is that text at those offsets, on sentence boundaries, in order, relevant, and the coverage still holds.
THE RELEVANCE FUNCTION is a plug-in: relevance(question, unit_text) -> a number from 0 to 1. The default is plain word overlap (deterministic and weak: it misses paraphrase); a better matcher can be supplied, but the rules above hold whatever it is, and a matcher that over-scores is what lets a wrong unit in: spot-check it.
HONEST LIMIT: matching words is not understanding. A unit can share the question's words and mean something else (a sarcastic remark, a quote of someone else's view). Each answer shows its quotations with dates so the reader decides; the owner can review answers before anyone else sees them."""
import re

STOP = frozenset("a an the of to in on at for and or is was were are be been it its this that with as by from my our your i me we you he she they them his her what who when where why how did do does would could should about will".split())
SENT_END = re.compile(r"(?<=[.!?])\s+")
MIN_SCORE, COVERAGE_MIN, STRONG = 0.5, 0.8, 0.9


class GroundedRefused(ValueError):
    pass


def terms(text: str) -> list:
    return sorted({w for w in re.findall(r"[^\W_]{3,}", str(text).casefold()) if w not in STOP})


def lexical_relevance(question: str, unit: str) -> float:
    q = terms(question)
    if not q:
        return 0.0
    u = set(terms(unit))
    return sum(1 for t in q if t in u) / len(q)


def split_units(text: str):
    """[(start, end, sentence)] for the complete sentences of a text, with offsets into the original."""
    out, pos = [], 0
    for m in SENT_END.finditer(text):
        if text[pos:m.start()].strip():
            out.append((pos, m.start(), text[pos:m.start()]))
        pos = m.end()
    if text[pos:].strip():
        out.append((pos, len(text), text[pos:]))
    return out


def _is_unit(text: str, start: int, end: int) -> bool:
    """True if text[start:end] is exactly one complete sentence of text."""
    return any(s == start and e == end for s, e, _ in split_units(text))


def candidates(entries):
    """entries: [{'entry': sha, 'i': position, 'at': time, 'speaker': ..., 'text': ..., 'segments': None | [{'start_ms','end_ms','text'}], 'media': None | {'sha256'..}}]
    -> a flat list of units in journal order. Only the owner's own, unredacted entries become units."""
    units = []
    for e in sorted(entries, key=lambda r: r["i"]):
        if e.get("speaker") != "owner" or e.get("redacted"):
            continue
        if e.get("segments"):
            for k, seg in enumerate(e["segments"]):
                units.append({"entry": e["entry"], "i": e["i"], "at": e["at"], "speaker": "owner", "start": k, "end": k + 1, "text": seg["text"],
                              "media": {"sha256": e["media"]["sha256"], "start_ms": seg["start_ms"], "end_ms": seg["end_ms"]}})
        else:
            for s, en, sent in split_units(e["text"]):
                units.append({"entry": e["entry"], "i": e["i"], "at": e["at"], "speaker": "owner", "start": s, "end": en, "text": sent, "media": None})
    return units


def ground(question: str, units, relevance=lexical_relevance, min_score: float = MIN_SCORE, coverage_min: float = COVERAGE_MIN, max_units: int = 8) -> dict:
    if not isinstance(question, str) or not question.strip() or len(question) > 1000:
        raise GroundedRefused("a question is 1 to 1000 characters")
    if not (isinstance(min_score, (int, float)) and not isinstance(min_score, bool) and 0 < min_score <= 1) or not (isinstance(coverage_min, (int, float)) and not isinstance(coverage_min, bool) and 0 < coverage_min <= 1):
        raise GroundedRefused("min_score and coverage_min are in (0, 1]")
    if isinstance(max_units, bool) or not isinstance(max_units, int) or not 1 <= max_units <= 50:
        raise GroundedRefused("max_units is 1 to 50")
    q = terms(question)
    none = {"answerable": False, "question_terms": q, "coverage": 0.0, "segments": [], "reason": "the journal does not answer this question"}
    if not q:
        return dict(none, reason="the question has no content words to match")
    scored = []
    for u in units:
        s = relevance(question, u["text"])
        if isinstance(s, bool) or not isinstance(s, (int, float)) or s != s:
            raise GroundedRefused("the relevance function must return a number from 0 to 1")
        s = max(0.0, min(1.0, float(s)))
        if s >= min_score:
            scored.append((s, u))
    if not scored:
        return none
    chosen, covered = [], set()
    for s, u in sorted(scored, key=lambda x: (-x[0], x[1]["i"], x[1]["start"])):         # best first, so the strongest bits are kept when there are more than max_units
        new = (set(terms(u["text"])) & set(q)) - covered
        if len(chosen) < max_units and (new or s >= STRONG):
            chosen.append((s, u))
            covered |= set(terms(u["text"])) & set(q)
    coverage = len(covered) / len(q)
    if any(sc >= STRONG for sc, _ in chosen):
        coverage = 1.0                                              # a matcher that says 'this unit answers it' (0.9 or more) is taken at its word: the words need not match one for one
    if coverage < coverage_min:
        return dict(none, coverage=round(coverage, 2), reason="what the journal says covers only part of this question")
    chosen.sort(key=lambda x: (x[1]["i"], x[1]["start"]))                                  # back into the order they were written
    segs = [{"entry": u["entry"], "start": u["start"], "end": u["end"], "text": u["text"], "at": u["at"], "score": round(s, 3), "media": u["media"]} for s, u in chosen]
    return {"answerable": True, "question_terms": q, "coverage": round(coverage, 2), "segments": segs, "reason": "answered from the owner's own recorded words"}


def render(answer: dict) -> str:
    """The answer as text: each quotation with its date, joined by line breaks. Nothing else is added."""
    if not answer.get("answerable"):
        return answer.get("reason", "the journal does not answer this question")
    lines = []
    for s in answer["segments"]:
        tag = "[%s]" % s["at"]
        if s["media"]:
            tag += " (recording %s.. %d-%d ms)" % (s["media"]["sha256"][:12], s["media"]["start_ms"], s["media"]["end_ms"])
        lines.append('%s "%s"' % (tag, s["text"]))
    return "\n".join(lines)


def verify_answer(question: str, answer, fetch_entry, relevance=lexical_relevance, min_score: float = MIN_SCORE, coverage_min: float = COVERAGE_MIN) -> bool:
    """fetch_entry(entry_sha) -> {'i','at','speaker','text','segments','media','redacted'} or None. Re-checks every rule; False on any failure; never raises."""
    try:
        if not isinstance(answer, dict) or answer.get("answerable") is not True:
            return False
        q = terms(question)
        if answer.get("question_terms") != q or not q:
            return False
        last, covered = (-1, -1), set()
        for seg in answer["segments"]:
            e = fetch_entry(seg["entry"])
            if e is None or e.get("speaker") != "owner" or e.get("redacted") or e["at"] != seg["at"]:
                return False
            if e.get("segments"):
                k = seg["start"]
                if seg["end"] != k + 1 or not 0 <= k < len(e["segments"]) or e["segments"][k]["text"] != seg["text"]:
                    return False
                m = seg["media"]
                real = e["segments"][k]
                if not m or m["sha256"] != e["media"]["sha256"] or m["start_ms"] != real["start_ms"] or m["end_ms"] != real["end_ms"]:
                    return False
            else:
                if seg["media"] is not None or e["text"][seg["start"]:seg["end"]] != seg["text"] or not _is_unit(e["text"], seg["start"], seg["end"]):
                    return False
            if relevance(question, seg["text"]) < min_score:
                return False
            order = (e["i"], seg["start"])
            if order <= last:
                return False
            last = order
            covered |= set(terms(seg["text"])) & set(q)
        strong = any(s["score"] >= STRONG and relevance(question, s["text"]) >= STRONG for s in answer["segments"])
        return (len(covered) / len(q) >= coverage_min or strong) and bool(answer["segments"])
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        return False
