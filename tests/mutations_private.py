"""Mutation check for the private journal: each rule removed in a COPY must make tests/redteam_2_private.py (or the base journal tests) fail.
Run: source SDK_FAMILY/env_family.sh; python tests/mutations_private.py"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
CR, GR, PV, LR = "crypto.py", "grounded.py", "private.py", "last_rites.py"
MUTATIONS = [
    ("split limits", CR, "if not 2 <= k <= n <= 16:", "if False:"),
    ("wrapped secret size", CR, "if not isinstance(secret, (bytes, bytearray)) or not 1 <= len(secret) <= 1024:", "if False:"),
    ("only the owner's own words", GR, 'if e.get("speaker") != "owner" or e.get("redacted"):', "if False:"),
    ("each unit must be relevant", GR, "if s >= min_score:", "if True:"),
    ("coverage must be enough", GR, "if coverage < coverage_min:", "if False:"),
    ("units stay in written order", GR, 'chosen.sort(key=lambda x: (x[1]["i"], x[1]["start"]))', "chosen.sort(key=lambda x: -x[0])"),
    ("each unit adds coverage or is strong", GR, "if len(chosen) < max_units and (new or s >= STRONG):", "if len(chosen) < max_units:"),
    ("verify: whole sentences only", GR, ' or not _is_unit(e["text"], seg["start"], seg["end"])', ""),
    ("verify: order", GR, "if order <= last:", "if False:"),
    ("verify: owner words only", GR, 'if e is None or e.get("speaker") != "owner" or e.get("redacted") or e["at"] != seg["at"]:', "if e is None:"),
    ("verify: relevance", GR, 'if relevance(question, seg["text"]) < min_score:', "if False:"),
    ("verify: the clip is the real clip", GR, 'if not m or m["sha256"] != e["media"]["sha256"] or m["start_ms"] != real["start_ms"] or m["end_ms"] != real["end_ms"]:', "if False:"),
    ("verify: the text is the real text", GR, ' e["text"][seg["start"]:seg["end"]] != seg["text"] or', ""),
    ("ciphertext is bound to its place", PV, 'return b"entry|%d|%s" % (rec["i"], rec["prev"].encode("ascii"))', 'return b"entry"'),
    ("grant signature", PV, 'if crypto.verify(self.owner_sign, "grant", body, rec["sig"]) and rec["grant_id"] == _sha(crypto.canonical(body))[:32]:', "if True:"),
    ("revoke signature", PV, 'if crypto.verify(self.owner_sign, "revoke", {"grant_id": rec["grant_id"]}, rec["sig"]) and rec["grant_id"] in self.grants:', 'if rec["grant_id"] in self.grants:'),
    ("legacy signature", PV, 'if crypto.verify(self.owner_sign, "legacy", signed, rec["sig"]) and rec["body"]["version"]', 'if rec["body"]["version"]'),
    ("legacy versions increment", PV, 'rec["body"]["version"] == (self.legacy["body"]["version"] + 1 if self.legacy else 1)', "True"),
    ("death threshold at load", PV, 'if good is not None and len(good) >= self.legacy["body"]["threshold"]:', "if good is not None:"),
    ("death threshold at declare", PV, 'if good is None or len(good) < self.legacy["body"]["threshold"]:', "if good is None:"),
    ("alive only during cooling at load", PV, ' and rec["at"] < d["body"]["cooling_until"]:', ":"),
    ("alive only during cooling", PV, 'if d is None or int(self._clock()) >= d["body"]["cooling_until"]:', "if d is None:"),
    ("cooling-off is respected", PV, 'return "legacy_effective" if any(now >= d["body"]["cooling_until"] for d, _ in live) else "death_declared_cooling"', 'return "legacy_effective"'),
    ("release needs an effective declaration", PV, 'if self.status(now) != "legacy_effective":', "if False:"),
    ("grants can be revoked and expire", PV, 'return gid not in self.revoked and (g["body"]["expires_at"] is None or now < g["body"]["expires_at"])', "return True"),
    ("the grantee's own box key", PV, ' or bytes.fromhex(g["body"]["grantee_box"]) != box.public:', ":"),
    ("beneficiaries only after the legacy is in effect", PV, 'if self.legacy is not None and self.status(now) == "legacy_effective" and self._S is not None:', "if self.legacy is not None and self._S is not None:"),
    ("scope filter on answers", PV, 'if rec["kind"] == "wish" or rec["redacted"] or not any(in_scope(sc, rec) for sc in scopes):', 'if rec["kind"] == "wish" or rec["redacted"]:'),
    ("wishes are not answers", PV, 'if rec["kind"] == "wish" or rec["redacted"] or not any(in_scope(sc, rec) for sc in scopes):', 'if rec["redacted"] or not any(in_scope(sc, rec) for sc in scopes):'),
    ("time scope", PV, 'return scope["from"] <= rec["at"] <= scope["to"]', "return True"),
    ("tag scope", PV, 'return bool(set(rec.get("tags", [])) & set(scope["tags"]))', "return True"),
    ("session scope", PV, 'return rec["session"] in scope["sessions"]', "return True"),
    ("every ask is recorded", PV, 'self.dag.record("JOURNAL_ACCESS", {', '(lambda *a: None)("JOURNAL_ACCESS", {'),
    ("answers-only grants carry no keys", PV, 'if mode == "full":\n            kg = crypto.new_key()', 'if True:\n            kg = crypto.new_key()'),
    ("the master key is required", PV, "if self._M is None:\n            raise Locked(\"the owner's master key is required for this\")", "if False:\n            raise Locked(\"the owner's master key is required for this\")"),
    ("wish signature", PV, 'if rec.get("kind") == "wish" and rec.get("osig") and crypto.verify(self.owner_sign, "wish", {"payload_sha256": rec["payload_sha256"], "assurance": rec["assurance"], "tags": rec["tags"]}, rec["osig"]):', 'if rec.get("kind") == "wish":'),
    ("witness signature", PV, ' and crypto.verify(bytes.fromhex(rec["witness_sign"]), "witness", {"wish": rec["wish"], "payload_sha256": w["payload_sha256"]}, rec["sig"])', ""),
    ("witnessed needs two", LR, '"status": "witnessed" if len(ws) >= 2 else "owner_signed"', '"status": "witnessed"'),
    ("withdrawn wishes are left out", LR, 'if not payload.get("revoked"):', "if True:"),
    ("statement: export signature", LR, 'if not crypto.verify(owner, "statement", body, packet["export_sig"]):', "if False:"),
    ("statement: text matches hash", LR, 'if _sha(w["payload_text"]) != w["payload_sha256"]:', "if False:"),
    ("statement: owner signature", LR, 'if not crypto.verify(owner, "wish", {"payload_sha256": w["payload_sha256"], "assurance": w["assurance"], "tags": w["tags"]}, w["owner_sig"]):', "if False:"),
    ("statement: inclusion proof", LR, 'if not merkle.verify(packet["journal_root"], w["record_sha256"], [tuple(x) for x in w["proof"]["path"]]):', "if False:"),
    ("statement: witness signatures", LR, 'if crypto.verify(bytes.fromhex(x["witness_sign"]), "witness", {"wish": w["record_sha256"], "payload_sha256": w["payload_sha256"]}, x["sig"]):', "if True:"),
    ("statement: the notice is fixed", LR, 'if packet["notice"] != NOTICE:', "if False:"),
    ("only the owner signs a wish", LR, "if signer.public != pj.owner_sign:\n        raise JournalRefused(\"only the owner signs a wish\")", "if False:\n        raise JournalRefused(\"only the owner signs a wish\")"),
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
    r = subprocess.run([sys.executable, "-W", "ignore", str(REPO / "tests" / "redteam_2_private.py")], capture_output=True, text=True, env=env, timeout=600)
    print(("killed   " if r.returncode != 0 else "SURVIVED ") + name, flush=True)
    if r.returncode == 0:
        survivors.append(name)
    shutil.rmtree(tmp, ignore_errors=True)
print("survivors:", survivors or "none")
