"""private.py - the PRIVATE journal: encrypted at rest, owner-only by default, shared by the owner's own choice in life, and released after death only as the owner decided beforehand.

WHO CAN READ WHAT
  the OWNER        holds the master key M. Every entry's text and media transcript is encrypted under its own random key, and that key is wrapped under M. Without M the journal is a chain of ciphertext:
                   the chain, the positions, speakers and times can be checked, nothing else is readable.
  a GRANTEE (in life)   the owner signs a grant: who (an identity key and a 'box' key for delivering secrets), what (scope: everything, some sessions, some tags, or a time range), how (mode) and until when.
                   mode 'full'          the grantee receives the entry keys for the scope, wrapped to their own box key: only they can open them, they read the entries themselves.
                   mode 'answers_only'  the grantee gets NO keys: they ask questions and the journal's answering service replies with grounded quotations (grounded.py); they never see anything else.
                   A grant can be revoked or can expire. Revoking stops the service from answering; a 'full' grantee who already received keys may have kept what they read: revocation cannot unsee it.
  after DEATH      the owner's LEGACY policy, set in life: named executors (any k of n) and a cooling-off period, and a list of beneficiaries each with a scope and a mode (the owner may allow 100%, or limit
                   exactly what each person gets; anyone not listed gets nothing). Executors do not get to read: a legacy key L is split among them (k of n); L unseals the answering service's key and the
                   beneficiaries' key bundles, but only a beneficiary's own box key opens their bundle. Death is DECLARED by k executors signing the same declaration; the owner (if alive) can cancel it during the
                   cooling-off period; after it, the executors present their shares and the journal opens as the policy says.
THE ANSWERING SERVICE is software: 'answers_only' is enforced by that software's rules (it holds the service key S), not by mathematics; the owner's lifetime S lives wrapped under M, after death it comes
back only from the executors' shares. Whoever controls that software at that moment could read everything: run it on a machine you trust.
EVERY ASK is recorded (a hash-only JOURNAL_ACCESS event on the chain: who by reference, how many quotations, whether it was answerable), so the owner and later the executors can audit use.
HONEST LIMITS: keys and signatures are plain-Python cryptography with no independent review. A death declaration rests on the executors' honesty: choose them and the threshold carefully. This module is access
control and evidence; it does not make a document legally valid (see last_rites.py)."""
import hashlib
import json
import time

from vega_custody.dag.dag import DagError, contains_credential
from vega_journal import crypto, grounded, merkle
from vega_journal.journal import Journal, JournalRefused, MARK, MAX_TEXT, SPEAKERS, _tokens, atomic

MODES = ("full", "answers_only")
DAY = 86400


class Locked(JournalRefused):
    pass


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _scope_ok(scope) -> dict:
    if not isinstance(scope, dict) or scope.get("kind") not in ("all", "sessions", "tags", "time"):
        raise JournalRefused("scope is all, sessions, tags or time")
    k = scope["kind"]
    if k == "all":
        return {"kind": "all"}
    if k in ("sessions", "tags"):
        key = k
        v = scope.get(key)
        if not isinstance(v, list) or not 1 <= len(v) <= 100 or not all(isinstance(x, str) and 1 <= len(x) <= 80 for x in v):
            raise JournalRefused("%s is a list of 1 to 100 short names" % key)
        return {"kind": k, key: sorted(set(v))}
    a, b = scope.get("from"), scope.get("to")
    if any(isinstance(x, bool) or not isinstance(x, int) or x < 0 for x in (a, b)) or a > b:
        raise JournalRefused("a time scope is from <= to, in whole seconds")
    return {"kind": "time", "from": a, "to": b}


def in_scope(scope, rec) -> bool:
    k = scope["kind"]
    if k == "all":
        return True
    if k == "sessions":
        return rec["session"] in scope["sessions"]
    if k == "tags":
        return bool(set(rec.get("tags", [])) & set(scope["tags"]))
    return scope["from"] <= rec["at"] <= scope["to"]


class PrivateJournal(Journal):
    def __init__(self, path, dag, owner_sign_public: bytes, master_key: bytes = None, clock=time.time):
        if not isinstance(owner_sign_public, (bytes, bytearray)) or len(owner_sign_public) != 32:
            raise JournalRefused("the owner's identity key is 32 bytes")
        self.owner_sign, self._M = bytes(owner_sign_public), (crypto._k(master_key) if master_key is not None else None)
        super().__init__(path, dag, clock)

    def _copy_config_from(self, other):
        self.owner_sign, self._M = other.owner_sign, other._M

    def _reset(self):
        super()._reset()
        self.init, self.grants, self.revoked, self.legacy, self.deaths, self.alive_ids, self.released = None, {}, set(), None, {}, set(), {}
        self.rejected, self._plain, self._S, self._L, self.wish_records, self.witness_sigs = 0, {}, None, None, {}, {}

    # ---- decrypting what we hold the keys for ------------------------------------------------------------------------------------------------
    @staticmethod
    def _aad(rec) -> bytes:
        return b"entry|%d|%s" % (rec["i"], rec["prev"].encode("ascii"))

    def _entry_key(self, rec):
        aad = self._aad(rec)
        try:
            if self._M is not None:
                w = bytes.fromhex(rec["wrap"])
                return crypto.open_(self._M, w[:12], w[12:], aad)
            if self._S is not None and rec.get("svc_wrap"):
                w = bytes.fromhex(rec["svc_wrap"])
                return crypto.open_(self._S, w[:12], w[12:], aad)
        except (crypto.CryptoRefused, ValueError):
            return None
        return None

    def _plain_of(self, rec) -> dict:
        got = self._plain.get(rec["sha256"])
        if got is not None:
            return got
        if not rec.get("enc"):
            return {"text": rec["text"], "segments": None}
        ke = self._entry_key(rec)
        if ke is None:
            raise Locked("this journal is locked: no key for this entry")
        try:
            data = json.loads(crypto.open_(ke, bytes.fromhex(rec["nonce"]), bytes.fromhex(rec["ct"]), self._aad(rec)).decode("utf-8"))
        except (crypto.CryptoRefused, ValueError) as exc:
            raise JournalRefused("an entry does not decrypt: it was altered") from exc
        self._plain[rec["sha256"]] = data
        return data

    def _index_text(self, rec) -> str:
        try:
            return self._plain_of(rec)["text"]
        except Locked:
            return ""

    def _reindex(self):
        self._index = {}
        for rec in self.entries.values():
            for tok in set(_tokens(self._index_text(rec))):
                self._index.setdefault(tok, []).append(rec["sha256"])

    # ---- applying the policy records (every one is checked against the owner's signature) ---------------------------------------------------------
    def _apply_extra(self, rec):
        t = rec["type"]
        try:
            if t == "init":
                if rec["i"] != 0 or bytes.fromhex(rec["owner_sign"]) != self.owner_sign or not crypto.verify(self.owner_sign, "init", {"owner_sign": rec["owner_sign"]}, rec["sig"]):
                    raise JournalRefused("this journal belongs to another owner or its first record is not the owner's")
                self.init = rec
                if self._M is not None:
                    w = bytes.fromhex(rec["service_wrap"])
                    self._S = crypto.open_(self._M, w[:12], w[12:], b"service")
            elif t == "grant":
                body = {k: rec[k] for k in ("grantee_sign", "grantee_box", "mode", "scope", "expires_at", "created")}
                if crypto.verify(self.owner_sign, "grant", body, rec["sig"]) and rec["grant_id"] == _sha(crypto.canonical(body))[:32]:
                    self.grants[rec["grant_id"]] = {"body": body, "key_wrap": rec.get("grant_key_wrap"), "wraps": dict(rec.get("entries") or {})}
                else:
                    self.rejected += 1
            elif t == "grant_add":
                if crypto.verify(self.owner_sign, "grant_add", {"grant_id": rec["grant_id"], "entries": rec["entries"]}, rec["sig"]) and rec["grant_id"] in self.grants:
                    self.grants[rec["grant_id"]]["wraps"].update(rec["entries"])
                else:
                    self.rejected += 1
            elif t == "revoke":
                if crypto.verify(self.owner_sign, "revoke", {"grant_id": rec["grant_id"]}, rec["sig"]) and rec["grant_id"] in self.grants:
                    self.revoked.add(rec["grant_id"])
                else:
                    self.rejected += 1
            elif t == "legacy":
                signed = {"body": rec["body"], "check": rec["check"], "sealed_service": rec["sealed_service"], "bundles_sha": _sha(crypto.canonical(rec["bundles"])), "shares_sha": _sha(crypto.canonical(rec["shares"]))}
                if crypto.verify(self.owner_sign, "legacy", signed, rec["sig"]) and rec["body"]["version"] == (self.legacy["body"]["version"] + 1 if self.legacy else 1):
                    self.legacy = rec
                    self._L = None
                else:
                    self.rejected += 1
            elif t == "death":
                self._apply_death(rec)
            elif t == "alive":
                d = self.deaths.get(rec["death_id"])
                if d and crypto.verify(self.owner_sign, "alive", {"death_id": rec["death_id"]}, rec["sig"]) and rec["at"] < d["body"]["cooling_until"]:
                    self.alive_ids.add(rec["death_id"])
                else:
                    self.rejected += 1
            elif t == "released":
                if rec["death_id"] in self.deaths:
                    self.released[rec["death_id"]] = rec
            elif t == "witness":
                w = self.wish_records.get(rec["wish"])
                if w and crypto.verify(bytes.fromhex(rec["witness_sign"]), "witness", {"wish": rec["wish"], "payload_sha256": w["payload_sha256"]}, rec["sig"]):
                    self.witness_sigs.setdefault(rec["wish"], {})[rec["witness_sign"]] = rec["sig"]
                else:
                    self.rejected += 1
            else:
                self.rejected += 1
        except JournalRefused:
            raise
        except (KeyError, TypeError, ValueError, AttributeError, crypto.CryptoRefused):
            self.rejected += 1

    def _death_good(self, body, sigs):
        """The executors whose signature on exactly this declaration is valid; None if the declaration is for another legacy version."""
        lg = self.legacy
        if lg is None or not isinstance(body, dict) or body.get("legacy_version") != lg["body"]["version"] or not isinstance(sigs, dict):
            return None
        if set(body) != {"legacy_version", "declared_at", "evidence_sha256", "cooling_until"}:
            return None                              # exactly the fields prepare_death builds: a missing or extra field is refused, never half-read later
        for k in ("legacy_version", "declared_at", "cooling_until"):
            if isinstance(body[k], bool) or not isinstance(body[k], int) or not 0 <= body[k] < 2 ** 40:
                return None
        ev = body["evidence_sha256"]
        if not isinstance(ev, str) or len(ev) != 64:
            return None
        if body["cooling_until"] != body["declared_at"] + lg["body"]["cooling_days"] * DAY:
            return None                              # the cooling-off length is the policy's, not whatever the signers wrote
        return {n for n, sg in sigs.items() if n in lg["body"]["executors"] and crypto.verify(bytes.fromhex(lg["body"]["executors"][n]["sign"]), "death", {"death": body}, sg)}

    def _apply_death(self, rec):
        good = self._death_good(rec["body"], rec["sigs"])
        if good is not None and len(good) >= self.legacy["body"]["threshold"]:
            # cooling-off can end no earlier than the policy length after the declaration was RECORDED, so a back-dated body cannot shorten it
            body = dict(rec["body"], cooling_until=max(rec["body"]["cooling_until"], int(rec["at"]) + self.legacy["body"]["cooling_days"] * DAY))
            self.deaths[rec["sha256"]] = {"body": body, "executors": sorted(good), "at": rec["at"]}
        else:
            self.rejected += 1

    def _record_wish(self, rec):
        if rec.get("kind") == "wish" and rec.get("osig") and crypto.verify(self.owner_sign, "wish", {"payload_sha256": rec["payload_sha256"], "assurance": rec["assurance"], "tags": rec["tags"]}, rec["osig"]):
            self.wish_records[rec["sha256"]] = rec

    def _apply(self, rec):
        super()._apply(rec)
        if rec["type"] == "entry" and rec.get("kind") == "wish":
            self._record_wish(rec)

    # ---- the owner's lifetime operations ----------------------------------------------------------------------------------------------------------
    def _need_owner(self):
        if self._M is None:
            raise Locked("the owner's master key is required for this")
        if self.init is None:
            raise JournalRefused("this journal has not been initialised: call initialise() first")

    @atomic
    def initialise(self, signer: crypto.Signer):
        """The first record: it names the owner and holds the service key wrapped under the master key."""
        if self.records:
            raise JournalRefused("already initialised")
        if self._M is None:
            raise Locked("the owner's master key is required")
        if signer.public != self.owner_sign:
            raise JournalRefused("the signer is not the owner this journal was opened for")
        S = crypto.new_key()
        n, ct = crypto.seal(self._M, S, b"service")
        ident = {"owner_sign": self.owner_sign.hex()}
        self._write("init", owner_sign=self.owner_sign.hex(), service_wrap=(n + ct).hex(), sig=signer.sign("init", ident))
        return self.init

    @atomic
    def _make_entry(self, speaker, text, session, kind, answers=None, tags=(), media=None, extra=None):
        self._need_owner()
        if speaker not in SPEAKERS or kind not in ("note", "question", "answer", "wish"):
            raise JournalRefused("bad speaker or kind")
        if not isinstance(session, str) or not 1 <= len(session) <= 80 or not session.isprintable():
            raise JournalRefused("session is a short printable label")
        tags = sorted(set(tags))
        if len(tags) > 20 or not all(isinstance(t, str) and 1 <= len(t) <= 40 for t in tags):
            raise JournalRefused("tags are up to 20 short names")
        segments, mref = None, None
        if media is not None:
            if not isinstance(media, dict) or media.get("type") not in ("video", "audio") or not isinstance(media.get("sha256"), str) or len(media["sha256"]) != 64 or \
                    isinstance(media.get("bytes"), bool) or not isinstance(media.get("bytes"), int) or media["bytes"] < 1 or not isinstance(media.get("segments"), list) or not 1 <= len(media["segments"]) <= 5000:
                raise JournalRefused("media is {type, sha256, bytes, segments}")
            prev_end = -1
            for sg in media["segments"]:
                if not isinstance(sg, dict) or any(isinstance(sg.get(k), bool) or not isinstance(sg.get(k), int) or sg[k] < 0 for k in ("start_ms", "end_ms")) or sg["end_ms"] <= sg["start_ms"] \
                        or sg["start_ms"] < prev_end or not isinstance(sg.get("text"), str) or not sg["text"].strip():
                    raise JournalRefused("segments run in order, each with start_ms < end_ms and some text")
                prev_end = sg["end_ms"]
            segments = [{"start_ms": s["start_ms"], "end_ms": s["end_ms"], "text": s["text"]} for s in media["segments"]]
            text = text or " ".join(s["text"] for s in segments)
            mref = {"type": media["type"], "sha256": media["sha256"], "bytes": media["bytes"]}
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT or "\x00" in text:
            raise JournalRefused("text is 1 to %d characters without NUL" % MAX_TEXT)
        redacted = contains_credential(text) or (segments is not None and any(contains_credential(s["text"]) for s in segments))
        payload = {"text": MARK if redacted else text, "segments": None if redacted else segments}
        i, prev = len(self.records), self.head
        aad = b"entry|%d|%s" % (i, prev.encode("ascii"))
        ke = crypto.new_key()
        nonce, ct = crypto.seal(ke, json.dumps(payload, sort_keys=True).encode("utf-8"), aad)
        wn, wc = crypto.seal(self._M, ke, aad)
        sn, sc = crypto.seal(self._S, ke, aad)
        fields = {"speaker": speaker, "session": session, "kind": kind, "answers": answers, "tags": tags, "media_ref": mref, "enc": 1, "nonce": nonce.hex(), "ct": ct.hex(), "wrap": (wn + wc).hex(),
                  "svc_wrap": (sn + sc).hex(), "pmac": crypto.mac(self._M, json.dumps(payload, sort_keys=True).encode("utf-8")), "redacted": redacted}
        if extra:
            fields.update(extra)
        rec = self._write("entry", **fields)
        return rec

    def add(self, speaker, text, session="default", kind="note", tags=(), media=None):
        if kind in ("answer", "wish"):
            raise JournalRefused("use answer() or wish() for that kind")
        return self._make_entry(speaker, text, session, kind, None, tags, media)

    def question(self, speaker, text, session="default", tags=()):
        return self._make_entry(speaker, text, session, "question", None, tags)

    def answer(self, question_id, speaker, text, session="default", tags=()):
        q = self.entries.get(question_id) if isinstance(question_id, str) else None
        if q is None or q["kind"] != "question":
            raise JournalRefused("an answer names the question it answers")
        return self._make_entry(speaker, text, session, "answer", question_id, tags)

    def read(self, entry_id: str) -> dict:
        """The owner reads an entry: {'text', 'segments'}."""
        self._need_owner()
        return dict(self._plain_of(self.get(entry_id)))

    def unlock_for_search(self):
        """Decrypt everything the owner can read into memory and build the search index (never written to disk)."""
        self._need_owner()
        for rec in self.entries.values():
            self._plain_of(rec)
        self._reindex()

    # ---- grants -----------------------------------------------------------------------------------------------------------------------------------------------
    def _entry_wraps(self, kg, scope, already=()):
        out = {}
        for sha, rec in self.entries.items():
            if sha in already or rec["redacted"] or not in_scope(scope, rec):
                continue
            ke = self._entry_key(rec)
            n, c = crypto.seal(kg, ke, sha.encode("ascii"))
            out[sha] = (n + c).hex()
        return out

    @atomic
    def grant(self, grantee_sign: bytes, grantee_box: bytes, mode: str, scope: dict, signer: crypto.Signer, expires_at: int = None) -> str:
        self._need_owner()
        if mode not in MODES or not isinstance(grantee_sign, (bytes, bytearray)) or len(grantee_sign) != 32 or not isinstance(grantee_box, (bytes, bytearray)) or len(grantee_box) != 32:
            raise JournalRefused("a grant has a mode, an identity key and a box key")
        if expires_at is not None and (isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= int(self._clock())):
            raise JournalRefused("expires_at is a future time in whole seconds")
        scope = _scope_ok(scope)
        body = {"grantee_sign": bytes(grantee_sign).hex(), "grantee_box": bytes(grantee_box).hex(), "mode": mode, "scope": scope, "expires_at": expires_at, "created": int(self._clock())}
        gid = _sha(crypto.canonical(body))[:32]
        extra = {}
        if mode == "full":
            kg = crypto.new_key()
            extra = {"grant_key_wrap": crypto.wrap_for(bytes(grantee_box), kg).hex(), "entries": self._entry_wraps(kg, scope)}
            self._grant_keys = getattr(self, "_grant_keys", {})
            self._grant_keys[gid] = kg
        self._write("grant", grant_id=gid, sig=signer.sign("grant", body), **body, **extra)
        return gid

    @atomic
    def share_new(self, grant_id: str, signer: crypto.Signer):
        """Wrap keys for entries written since a 'full' grant was made, for the same scope. Needs the grant key, which the owner's process keeps only while it runs."""
        self._need_owner()
        g = self.grants.get(grant_id)
        kg = getattr(self, "_grant_keys", {}).get(grant_id)
        if g is None or g["body"]["mode"] != "full" or kg is None or grant_id in self.revoked:
            raise JournalRefused("no active full grant with a key to extend")
        add = self._entry_wraps(kg, g["body"]["scope"], already=g["wraps"])
        body = {"grant_id": grant_id, "entries": add}
        self._write("grant_add", sig=signer.sign("grant_add", body), **body)
        return len(add)

    @atomic
    def revoke(self, grant_id: str, signer: crypto.Signer):
        self._need_owner()
        if grant_id not in self.grants or grant_id in self.revoked:
            raise JournalRefused("no such active grant")
        self._write("revoke", grant_id=grant_id, sig=signer.sign("revoke", {"grant_id": grant_id}))

    def _active(self, g, gid, now) -> bool:
        return gid not in self.revoked and (g["body"]["expires_at"] is None or now < g["body"]["expires_at"])

    def grantee_open(self, grant_id: str, box: crypto.KeyPair, now: int = None) -> dict:
        """A 'full' grantee opens their own copy: {entry id: {'text', 'segments'}}. Needs their box private key; the journal's own keys are not involved."""
        now = int(self._clock()) if now is None else now
        g = self.grants.get(grant_id)
        if g is None or g["body"]["mode"] != "full" or not self._active(g, grant_id, now) or bytes.fromhex(g["body"]["grantee_box"]) != box.public:
            raise JournalRefused("no active full grant for this key")
        kg = box.unwrap(bytes.fromhex(g["key_wrap"]))
        out = {}
        for sha, w in g["wraps"].items():
            wb = bytes.fromhex(w)
            ke = crypto.open_(kg, wb[:12], wb[12:], sha.encode("ascii"))
            rec = self.entries[sha]
            out[sha] = json.loads(crypto.open_(ke, bytes.fromhex(rec["nonce"]), bytes.fromhex(rec["ct"]), self._aad(rec)).decode("utf-8"))
        return out

    # ---- legacy -------------------------------------------------------------------------------------------------------------------------------------------------
    @atomic
    def set_legacy(self, executors: dict, threshold: int, cooling_days: int, beneficiaries: list, signer: crypto.Signer):
        self._need_owner()
        if not isinstance(executors, dict) or not 2 <= len(executors) <= 12 or isinstance(threshold, bool) or not isinstance(threshold, int) or not 2 <= threshold <= len(executors):
            raise JournalRefused("2 to 12 executors and a threshold of at least 2")
        if isinstance(cooling_days, bool) or not isinstance(cooling_days, int) or not 1 <= cooling_days <= 365:
            raise JournalRefused("cooling_days is 1 to 365")
        ex = {}
        for name, e in executors.items():
            if not isinstance(name, str) or not 1 <= len(name) <= 40 or not isinstance(e, dict) or len(bytes.fromhex(e["sign"])) != 32 or len(bytes.fromhex(e["box"])) != 32:
                raise JournalRefused("an executor has a name, an identity key and a box key")
            ex[name] = {"sign": e["sign"], "box": e["box"]}
        bens, seen = [], set()
        for b in beneficiaries or []:
            if not isinstance(b, dict) or b.get("name") in seen or b.get("mode") not in MODES or not isinstance(b.get("name"), str):
                raise JournalRefused("a beneficiary has a unique name, an identity key, a box key, a mode and a scope")
            seen.add(b["name"])
            bens.append({"name": b["name"], "sign": b["sign"], "box": b["box"], "mode": b["mode"], "scope": _scope_ok(b["scope"])})
        names = sorted(ex)
        L = crypto.new_key()
        shares, check = crypto.split(L, threshold, len(names))
        share_wraps = {n: crypto.wrap_for(bytes.fromhex(ex[n]["box"]), bytes([x]) + sh).hex() for n, (x, sh) in zip(names, shares)}
        sn, sc = crypto.seal(L, self._S, b"legacy-service")
        bundles = {}
        for b in bens:
            if b["mode"] == "full":
                kg = crypto.new_key()
                bundle = {"grant_key_wrap": crypto.wrap_for(bytes.fromhex(b["box"]), kg).hex(), "entries": self._entry_wraps(kg, b["scope"])}
                bn, bc = crypto.seal(L, json.dumps(bundle, sort_keys=True).encode("utf-8"), b"legacy-bundle|" + b["name"].encode("utf-8"))
                bundles[b["name"]] = (bn + bc).hex()
        body = {"version": (self.legacy["body"]["version"] + 1) if self.legacy else 1, "executors": ex, "threshold": threshold, "cooling_days": cooling_days, "beneficiaries": bens, "created": int(self._clock())}
        ln, lc = crypto.seal(self._M, L, b"legacy-l")
        sealed = (sn + sc).hex()
        signed = {"body": body, "check": check, "sealed_service": sealed, "bundles_sha": _sha(crypto.canonical(bundles)), "shares_sha": _sha(crypto.canonical(share_wraps))}
        self._write("legacy", body=body, check=check, sealed_service=sealed, bundles=bundles, shares=share_wraps, l_wrap=(ln + lc).hex(), sig=signer.sign("legacy", signed))
        return body["version"]

    def prepare_death(self, evidence_sha256: str, now: int = None) -> dict:
        """The declaration the executors sign. Anyone holding the journal can build it; it names the legacy version and the day the cooling-off ends."""
        if self.legacy is None:
            raise JournalRefused("no legacy policy is set")
        if not isinstance(evidence_sha256, str) or len(evidence_sha256) != 64:
            raise JournalRefused("evidence is the sha256 of the supporting document (for example a death certificate)")
        now = int(self._clock()) if now is None else now
        return {"legacy_version": self.legacy["body"]["version"], "declared_at": now, "evidence_sha256": evidence_sha256, "cooling_until": now + self.legacy["body"]["cooling_days"] * DAY}

    @atomic
    def declare_death(self, body: dict, sigs: dict) -> str:
        if self.legacy is None:
            raise JournalRefused("no legacy policy is set")
        good = self._death_good(body, sigs)
        if good is None or len(good) < self.legacy["body"]["threshold"]:
            raise JournalRefused("not enough valid executor signatures on this declaration")
        self._write("death", body=body, sigs=sigs)
        return self.records[-1]["sha256"]

    @atomic
    def alive(self, death_id: str, signer: crypto.Signer):
        self._need_owner()
        d = self.deaths.get(death_id)
        if d is None or int(self._clock()) >= d["body"]["cooling_until"]:
            raise JournalRefused("no such declaration, or its cooling-off period is over")
        self._write("alive", death_id=death_id, sig=signer.sign("alive", {"death_id": death_id}))

    def status(self, now: int = None) -> str:
        now = int(self._clock()) if now is None else now
        live = [(d, i) for i, d in self.deaths.items() if i not in self.alive_ids]
        if not live:
            return "living"
        return "legacy_effective" if any(now >= d["body"]["cooling_until"] for d, _ in live) else "death_declared_cooling"

    @atomic
    def release(self, shares: dict, now: int = None) -> bool:
        """Executors present their decrypted shares {name: bytes(x + share)}. Needs an effective, uncancelled declaration. On success the service key is recovered in memory and the policy applies."""
        if self.status(now) != "legacy_effective":
            raise JournalRefused("the legacy policy is not in effect")
        lg = self.legacy
        try:
            n = len(lg["body"]["executors"])
            L = crypto.combine([(s[0], bytes(s[1:])) for s in shares.values()], lg["check"], lg["body"]["threshold"], n)
            w = bytes.fromhex(lg["sealed_service"])
            S = crypto.open_(L, w[:12], w[12:], b"legacy-service")
        except (crypto.CryptoRefused, ValueError, TypeError, IndexError) as exc:
            raise JournalRefused("the shares do not open the journal: %s" % exc) from exc
        self._L, self._S = L, S
        self._plain = {}
        self._reindex()
        did = [i for i, d in self.deaths.items() if i not in self.alive_ids][0]
        if did not in self.released:
            self._write("released", death_id=did, executors=sorted(shares), count=len(shares))
        return True

    def beneficiary_open(self, name: str, box: crypto.KeyPair) -> dict:
        """A 'full' beneficiary opens their bundle after release: {entry id: {'text', 'segments'}}."""
        if self._L is None or self.legacy is None:
            raise JournalRefused("the journal has not been released")
        ben = next((b for b in self.legacy["body"]["beneficiaries"] if b["name"] == name and b["mode"] == "full"), None)
        if ben is None or bytes.fromhex(ben["box"]) != box.public or name not in self.legacy["bundles"]:
            raise JournalRefused("no full bundle for this beneficiary and key")
        wb = bytes.fromhex(self.legacy["bundles"][name])
        bundle = json.loads(crypto.open_(self._L, wb[:12], wb[12:], b"legacy-bundle|" + name.encode("utf-8")).decode("utf-8"))
        kg = box.unwrap(bytes.fromhex(bundle["grant_key_wrap"]))
        out = {}
        for sha, w in bundle["entries"].items():
            b = bytes.fromhex(w)
            ke = crypto.open_(kg, b[:12], b[12:], sha.encode("ascii"))
            rec = self.entries[sha]
            out[sha] = json.loads(crypto.open_(ke, bytes.fromhex(rec["nonce"]), bytes.fromhex(rec["ct"]), self._aad(rec)).decode("utf-8"))
        return out

    # ---- asking -------------------------------------------------------------------------------------------------------------------------------------------------------
    def _authority(self, party: bytes, now: int):
        """-> (label, scope) or raises. The owner sees everything; a grantee their active grants; a beneficiary only after the legacy policy is in effect and released."""
        if bytes(party) == self.owner_sign:
            if self._M is None:
                raise Locked("the owner's master key is required")
            return "owner", {"kind": "all"}
        scopes = [g["body"]["scope"] for gid, g in self.grants.items() if bytes.fromhex(g["body"]["grantee_sign"]) == bytes(party) and self._active(g, gid, now)]
        if self._M is None and not scopes and self.legacy is None:
            raise JournalRefused("no access")
        if scopes:
            if self._S is None:
                raise Locked("the answering service is not running")
            return "grantee", scopes
        if self.legacy is not None and self.status(now) == "legacy_effective" and self._S is not None:
            ben = [b["scope"] for b in self.legacy["body"]["beneficiaries"] if bytes.fromhex(b["sign"]) == bytes(party)]
            if ben:
                return "beneficiary", ben
        raise JournalRefused("no access")

    def ask(self, party: bytes, question: str, relevance=grounded.lexical_relevance, now: int = None, **kw) -> dict:
        """A grounded answer to a question, for whoever is allowed to ask. Always recorded on the chain (hash only)."""
        now = int(self._clock()) if now is None else now
        label, scopes = self._authority(party, now)
        scopes = [scopes] if isinstance(scopes, dict) else scopes
        pool = []
        for sha, rec in self.entries.items():
            if rec["kind"] == "wish" or rec["redacted"] or not any(in_scope(sc, rec) for sc in scopes):
                continue
            p = self._plain_of(rec)
            pool.append({"entry": sha, "i": rec["i"], "at": rec["at"], "speaker": rec["speaker"], "text": p["text"], "segments": p["segments"], "media": rec["media_ref"], "redacted": False})
        ans = grounded.ground(question, grounded.candidates(pool), relevance, **kw)
        try:
            self.dag.record("JOURNAL_ACCESS", {"party_ref": _sha(bytes(party))[:16], "as": label, "answerable": ans["answerable"], "units": len(ans["segments"]), "question_sha256": _sha(question.encode("utf-8"))})
        except DagError as exc:
            raise JournalRefused("the access could not be recorded: nothing was answered: %s" % exc) from exc
        return ans

    def verify_answer(self, question: str, answer: dict, relevance=grounded.lexical_relevance, **kw) -> bool:
        def fetch(sha):
            rec = self.entries.get(sha)
            if rec is None:
                return None
            p = self._plain_of(rec)
            return {"i": rec["i"], "at": rec["at"], "speaker": rec["speaker"], "text": p["text"], "segments": p["segments"], "media": rec["media_ref"], "redacted": rec["redacted"]}
        return grounded.verify_answer(question, answer, fetch, relevance, **kw)

