"""Mutation check for the journal: each rule removed in a COPY must make tests/redteam_1_journal.py fail."""
import os, pathlib, shutil, subprocess, sys, tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
JN, MK = "journal.py", "merkle.py"
MUTATIONS = [
    ("records link to the previous hash", JN, 'rec.get("prev") != prev or ', ""),
    ("record hash is checked on load", JN, ' or rec.get("sha256") != _hash(rec)', ""),
    ("positions must run in order", JN, 'rec.get("i") != n or ', ""),
    ("a half-written line is refused", JN, r'if data and not data.endswith("\n"):', "if False:"),
    ("the clock cannot run backwards", JN, 'if self.records and now < self.records[-1]["at"]:', "if False:"),
    ("the chain is written before the file", JN, 'self.dag.record("JOURNAL_RECORD", {"type": rec_type, "position": rec["i"], "record_sha256": rec["sha256"]})', "pass"),
    ("credentials are redacted", JN, "redacted = contains_credential(text)", "redacted = False"),
    ("redacted entries cannot anchor an idea", JN, 'if e["redacted"]:', "if False:"),
    ("an answer names a question", JN, 'if q is None or q["kind"] != "question":', "if False:"),
    ("a plain add cannot make an answer", JN, 'if kind == "answer":', "if False:"),
    ("text size cap", JN, "len(text) > MAX_TEXT or ", ""),
    ("NUL refused", JN, r' or "\x00" in text', ""),
    ("the quote must lie inside the entry", JN, "not 0 <= start < end <= len(e[\"text\"])", "False"),
    ("duplicate ideas refused", JN, "if name.casefold() in self.ideas:", "if False:"),
    ("no cycles", JN, "if x == c:\n                raise JournalRefused", "if False:\n                raise JournalRefused"),
    ("no self edge", JN, "if c == p:", "if False:"),
    ("receipt refuses another origin", JN, "if fa is None:\n            raise JournalRefused(\"no anchor for this idea has origin", "if False:\n            raise JournalRefused(\"no anchor for this idea has origin"),
    ("origin is the speaker", JN, 'origin=e["speaker"])\n\n    def anchor', 'origin="owner")\n\n    def anchor'),
    ("earliest anchor wins", JN, "rows = sorted((x for x in a if origin is None or x[\"origin\"] == origin), key=lambda x: x[\"i\"])", "rows = [x for x in a if origin is None or x[\"origin\"] == origin]"),
    ("first use is the earliest", JN, 'rows = sorted((self.entries[h] for h in (cand or [])), key=lambda r: r["i"])', 'rows = [self.entries[h] for h in (cand or [])]'),
    ("search speaker filter", JN, 'if speaker is None or self.entries[h]["speaker"] == speaker]', "]"),
    ("receipt quote check", JN, 'return quote_text is None or hashlib.sha256(quote_text.encode("utf-8")).hexdigest() == receipt["quote_sha256"]', "return True"),
    ("receipt path check", JN, 'if not merkle.verify(receipt["journal_root"], receipt["entry_sha256"], [tuple(x) for x in receipt["proof"]["path"]]):\n            return False', "if False:\n            return False"),
    ("merkle leaf prefix", MK, r'return hashlib.sha256(b"\x00" + h).digest()', "return hashlib.sha256(h).digest()"),
    ("merkle node prefix", MK, r'return hashlib.sha256(b"\x01" + a + b).digest()', "return hashlib.sha256(a + b).digest()"),
    ("merkle side check", MK, 'if side not in ("L", "R"):\n                return False', "if False:\n                return False"),
    ("merkle root compare", MK, "return node.hex() == root_hex", "return True"),
]
if __name__ != "__main__":
    MUTATIONS = []
survivors = []
for name, fname, old, new in MUTATIONS:
    tmp = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(REPO / "src" / "vega_journal", tmp / "vega_journal")
    f = tmp / "vega_journal" / fname
    text = f.read_text(encoding="utf-8")
    if old not in text:
        print("CANNOT APPLY", name)
        survivors.append(name + " (could not apply)")
        continue
    f.write_text(text.replace(old, new, 1), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp) + os.pathsep + env.get("PYTHONPATH", "")
    r = subprocess.run([sys.executable, "-W", "ignore", str(REPO / "tests" / "redteam_1_journal.py")], capture_output=True, text=True, env=env, timeout=600)
    print(("killed   " if r.returncode != 0 else "SURVIVED ") + name, flush=True)
    if r.returncode == 0:
        survivors.append(name)
    shutil.rmtree(tmp, ignore_errors=True)
print("survivors:", survivors or "none")
