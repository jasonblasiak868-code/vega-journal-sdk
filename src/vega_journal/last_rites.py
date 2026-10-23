"""last_rites.py - Section 4 of the journal: the owner's wishes for what happens to their things and their memory, recorded so that anyone can later check they are really the owner's, when they were written and
that nobody changed them.

  wish(...)                 an owner-signed entry (private like every entry): what, to whom, why; a later wish with the same id replaces the earlier one (the history stays in the chain); a wish can be withdrawn.
                            The signature covers the wish's text hash, the identity assurance level the owner had when writing it (from the identity SDK: level 4 means the strongest factors were used), and its tags.
  witness(...)              another person signs the same wish text with their own key: two or more witnesses is the usual start of a formal execution. This records that they saw it; it is not a notary.
  statement_of_wishes(...)  the owner exports a packet: each current wish in plain text, with its signature, its witnesses, its place in the chain and a Merkle proof against the journal root; the packet is signed too.
  verify_statement(packet)  anyone can re-check a packet from the packet alone: signatures, hashes, witnesses and inclusion. It returns a list of problems (empty means it checks out).
WHAT THIS IS NOT: it is NOT a will and it does not transfer anything. Wills have formal requirements that differ by place (writing, signature, witnesses, sometimes notarization), and what weight a court gives to
informal writings, emails or recordings when there is no will depends on the law and the facts of that place; I have not checked any jurisdiction's rules for this module. What the packet gives a lawyer or a court is EVIDENCE:
a tamper-evident, signed record of what the owner wrote and when. The reliable way to have wishes followed is a valid will drawn up with an attorney; show them the packet. Nothing here is legal advice."""
import hashlib
import json
import re

from vega_custody.dag.dag import contains_credential
from vega_journal import crypto, merkle
from vega_journal.journal import JournalRefused

NOTICE = ("This is a statement of the owner's wishes, recorded in a tamper-evident journal and signed with the owner's key. It is NOT a will and does not by itself transfer anything. Whether a court "
          "gives it any weight depends on the law of the place and the facts. A will drawn and executed under the law of the owner's place is the reliable way to have wishes followed: show this to an attorney.")
KINDS = ("property", "digital_assets", "funeral", "care", "message", "other")
ID = re.compile(r"^[a-z0-9][a-z0-9_-]{1,39}$")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _tags(extra=()):
    return sorted(set(extra) | {"last_rites"})


def wish(pj, signer: crypto.Signer, wish_id: str, kind: str, item: str, recipient: str, note: str = "", assurance: int = None, revoked: bool = False):
    if not isinstance(wish_id, str) or not ID.fullmatch(wish_id) or kind not in KINDS:
        raise JournalRefused("a wish has a plain id and a kind from %s" % (KINDS,))
    for name, v, lo, hi in (("item", item, 1, 500), ("recipient", recipient, 0, 200), ("note", note, 0, 2000)):
        if not isinstance(v, str) or not lo <= len(v) <= hi:
            raise JournalRefused("%s is %d to %d characters" % (name, lo, hi))
    if any(contains_credential(v) for v in (wish_id, item, recipient, note)):
        raise JournalRefused("a wish cannot contain a credential-shaped value: the journal would redact it and the wish would be lost; leave the secret out and say where it is kept")
    if assurance is not None and (isinstance(assurance, bool) or not isinstance(assurance, int) or not 0 <= assurance <= 4):
        raise JournalRefused("assurance is the identity level 0 to 4, or None")
    if signer.public != pj.owner_sign:
        raise JournalRefused("only the owner signs a wish")
    prev = [r for r in current_records(pj) if r[0] == wish_id]
    payload = {"wish_id": wish_id, "kind": kind, "item": item, "recipient": recipient, "note": note, "revoked": bool(revoked), "supersedes": prev[-1][1]["sha256"] if prev else None}
    text = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    tags = _tags()
    extra = {"payload_sha256": _sha(text), "assurance": assurance, "osig": signer.sign("wish", {"payload_sha256": _sha(text), "assurance": assurance, "tags": tags})}
    return pj._make_entry("owner", text, "last_rites", "wish", None, tags, None, extra)


def current_records(pj):
    """[(wish_id, record)] for every valid wish record, in the order written."""
    out = []
    for rec in sorted(pj.wish_records.values(), key=lambda r: r["i"]):
        try:
            out.append((json.loads(pj._plain_of(rec)["text"])["wish_id"], rec))
        except (ValueError, KeyError, TypeError):
            continue
    return out


def current_wishes(pj):
    """The latest version of each wish that has not been withdrawn: [(record, payload dict)]."""
    latest = {}
    for wid, rec in current_records(pj):
        latest[wid] = rec
    out = []
    for wid, rec in latest.items():
        payload = json.loads(pj._plain_of(rec)["text"])
        if not payload.get("revoked"):
            out.append((rec, payload))
    return sorted(out, key=lambda x: x[0]["i"])


def witness(pj, wish_record_sha: str, witness_signer: crypto.Signer):
    rec = pj.wish_records.get(wish_record_sha)
    if rec is None:
        raise JournalRefused("no such valid wish record")
    if witness_signer.public == pj.owner_sign:
        raise JournalRefused("the owner cannot witness their own wish")
    body = {"wish": wish_record_sha, "payload_sha256": rec["payload_sha256"]}
    pj._write("witness", wish=wish_record_sha, witness_sign=witness_signer.public.hex(), sig=witness_signer.sign("witness", body))


def statement_of_wishes(pj, signer: crypto.Signer, now: int = None) -> dict:
    if signer.public != pj.owner_sign:
        raise JournalRefused("only the owner exports the statement")
    pj._need_owner()
    wishes = []
    for rec, payload in current_wishes(pj):
        text = pj._plain_of(rec)["text"]
        ws = pj.witness_sigs.get(rec["sha256"], {})
        wishes.append({"wish_id": payload["wish_id"], "payload_text": text, "payload_sha256": rec["payload_sha256"], "record_sha256": rec["sha256"], "position": rec["i"], "recorded_at": rec["at"],
                       "owner_sig": rec["osig"], "assurance": rec["assurance"], "tags": rec["tags"], "witnesses": [{"witness_sign": k, "sig": v} for k, v in sorted(ws.items())],
                       "status": "witnessed" if len([k for k in ws if k != pj.owner_sign.hex()]) >= 2 else "owner_signed", "proof": pj.inclusion_proof(rec["sha256"])})
    body = {"notice": NOTICE, "owner_sign": pj.owner_sign.hex(), "exported_at": int(pj._clock()) if now is None else now, "journal_root": pj.root(), "journal_size": len(pj.records), "chain_head": pj.head, "wishes": wishes,
            "assurance_note": "assurance is the identity level the owner reported when signing (see the identity SDK); verify that assertion separately"}
    return dict(body, export_sig=signer.sign("statement", body))


def verify_statement(packet) -> list:
    """Problems found in a statement of wishes, checked from the packet alone. Empty list = it checks out. Never raises."""
    problems = []
    try:
        body = {k: v for k, v in packet.items() if k != "export_sig"}
        owner = bytes.fromhex(packet["owner_sign"])
        if not crypto.verify(owner, "statement", body, packet["export_sig"]):
            problems.append("the packet's own signature does not verify")
        if packet["notice"] != NOTICE:
            problems.append("the notice was changed")
        seen = set()
        for w in packet["wishes"]:
            wid = w.get("wish_id", "?")
            if _sha(w["payload_text"]) != w["payload_sha256"]:
                problems.append("%s: the text does not match its hash" % wid)
            if not crypto.verify(owner, "wish", {"payload_sha256": w["payload_sha256"], "assurance": w["assurance"], "tags": w["tags"]}, w["owner_sig"]):
                problems.append("%s: the owner's signature does not verify" % wid)
            if not merkle.verify(packet["journal_root"], w["record_sha256"], [tuple(x) for x in w["proof"]["path"]]):
                problems.append("%s: not in the journal root" % wid)
            good = set()                                    # DISTINCT witness keys with a valid signature; the owner cannot witness their own wish
            for x in w["witnesses"]:
                key = x["witness_sign"]
                if crypto.verify(bytes.fromhex(key), "witness", {"wish": w["record_sha256"], "payload_sha256": w["payload_sha256"]}, x["sig"]):
                    if key == packet["owner_sign"]:
                        problems.append("%s: the owner is listed as their own witness" % wid)
                    elif key in good:
                        problems.append("%s: the same witness is listed twice" % wid)
                    else:
                        good.add(key)
                else:
                    problems.append("%s: a witness signature does not verify" % wid)
            if w["status"] != ("witnessed" if len(good) >= 2 else "owner_signed"):
                problems.append("%s: the status does not match the witnesses" % wid)
            if json.loads(w["payload_text"]).get("wish_id") != w["wish_id"] or w["wish_id"] in seen:
                problems.append("%s: wrong or repeated wish id" % wid)
            seen.add(w["wish_id"])
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        problems.append("the packet is malformed: %s" % type(exc).__name__)
    return problems
