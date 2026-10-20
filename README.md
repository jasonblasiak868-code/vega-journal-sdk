# vega-journal-sdk

![vega-journal-sdk](assets/tile.svg)

A private, verbatim, hash-chained question-and-answer journal with a thought-genome map: every idea is anchored to its first appearance in the owner's own words, and a Merkle receipt proves it was in the journal at that time. The journal is encrypted at rest; the owner decides who reads what, and a legacy policy releases selected entries after death only as the owner prescribed.

> **Licensing.** Source-available, not open source. Free for personal use; free for registered small businesses (under US$1M revenue and valuation); everyone else needs a commercial license (see LICENSE; for a commercial license write to jasonblasiak.ai.mail@gmail.com). Patent pending (U.S. provisional application 64/178,949 and others). Draft licence text, not yet reviewed by an attorney.

---

## At a glance

| Item | Detail |
|------|--------|
| **Version** | 0.1.0 |
| **Python** | >=3.10 |
| **Dependencies** | cryptography>=42, vega-custody-sdk, vega-superproof-sdk |
| **Tests** | 69 tests in 2 files (all passing) |
| **Mutation tests** | 57 killed, 1 could not apply, 1 survived (redundant self-edge check caught by cycle detection) |
| **Status** | All modules BUILT and tested |
| **Layer** | 0 record (foundation) — the append-only chain everything writes to |

---

## Table of contents

- [End-to-end functions](#end-to-end-functions)
- [Controls](#controls)
- [What it cannot do](#what-it-cannot-do)
- [Platform support](#platform-support)
- [Standalone & unified install](#standalone--unified-install)
- [Diagnostic control surface](#diagnostic-control-surface)
- [Fail-closed constraints & custom constraints](#fail-closed-constraints--custom-constraints)
- [Tests](#tests)
- [Status & honesty](#status--honesty)

---

## End-to-end functions

1. **Initialise** — owner provides master key and signing key; journal writes an `init` record binding the service key to the master key.
2. **Record entries** — owner adds notes, questions, answers, or wishes; each entry is encrypted with a unique key wrapped to the master key and the service key, then appended to the hash chain.
3. **Anchor ideas** — owner marks exact quotations as named ideas with origin (owner, model, observer); edges record "this idea grew from that idea" with cycle rejection.
4. **Search and first-use** — word-overlap search over decrypted entries; `first_use(term)` returns the earliest entry containing every word.
5. **Conception receipts** — `conception_receipt(idea, origin)` returns the earliest anchor by that origin, the journal root, and a Merkle inclusion proof verifiable by anyone.
6. **Grant access (lifetime)** — owner signs a grant for a grantee's identity/box key: mode `full` (keys delivered, grantee decrypts) or `answers_only` (no keys, grantee asks grounded questions). Scope: sessions, tags, time, or all. Grants expire or can be revoked.
7. **Ask grounded questions** — any authorised party asks; the journal returns only whole sentences or whole transcript segments spoken by the owner, each relevant on its own, in written order, with nothing added. Refuses if coverage is below threshold. Every ask is recorded on the chain (hash only).
8. **Set legacy policy** — owner names executors (k of n), cooling-off period, and beneficiaries with per-beneficiary scope and mode. The legacy key is split among executors; the service key and beneficiary bundles are sealed under it.
9. **Declare death** — k executors sign the same declaration; during cooling-off the owner can cancel with an `alive` record.
10. **Release** — after cooling-off, executors present shares; the journal recovers the service key, applies the policy, and records the release.
11. **Beneficiary access** — `full` beneficiaries decrypt their bundles; `answers_only` beneficiaries ask grounded questions within their scope.
12. **Last-rites wishes** — owner signs wishes (property, digital_assets, funeral, care, message, other) with assurance level; witnesses can co-sign; `statement_of_wishes` exports a verifiable packet with Merkle proofs; `verify_statement` checks it from the packet alone.

---

## Controls

| Control | What it does |
|---------|--------------|
| `Journal(path, dag, clock)` | Base journal: verbatim append-only chain, ideas, edges, search, receipts, Merkle proofs. |
| `PrivateJournal(path, dag, owner_sign_public, master_key, clock)` | Encrypted journal: adds encryption, grants, legacy, last-rites, grounded ask. |
| `initialise(signer)` | Writes the `init` record; requires owner's master key and matching signer. |
| `add/question/answer/wish(...)` | Append encrypted entries; validate speaker, kind, session, tags, media, size, NUL, credentials. |
| `read(entry_id)` | Owner-only decryption of one entry. |
| `unlock_for_search()` | Decrypts all entries into memory, builds search index (never written to disk). |
| `grant(grantee_sign, grantee_box, mode, scope, signer, expires_at)` | Creates a signed grant record; `full` mode wraps entry keys to grantee's box key. |
| `share_new(grant_id, signer)` | Wraps keys for entries added since grant, for same scope (needs grant key in memory). |
| `revoke(grant_id, signer)` | Marks grant revoked; recorded on chain. |
| `grantee_open(grant_id, box)` | `full` grantee decrypts their entries using their box private key (no journal keys needed). |
| `set_legacy(executors, threshold, cooling_days, beneficiaries, signer)` | Creates legacy policy: splits legacy key, seals service key and beneficiary bundles. |
| `prepare_death(evidence_sha256)` | Builds the declaration executors sign (legacy version, declared_at, evidence hash, cooling_until). |
| `declare_death(body, sigs)` | Verifies k-of-n executor signatures on identical declaration for current legacy version; refuses otherwise. |
| `alive(death_id, signer)` | Owner cancels a declaration during cooling-off. |
| `status(now)` | Returns `living`, `death_declared_cooling`, or `legacy_effective`. |
| `release(shares, now)` | Combines executor shares, recovers legacy key, opens service key, rebuilds index, records release. |
| `beneficiary_open(name, box)` | `full` beneficiary decrypts their bundle after release. |
| `ask(party, question, relevance, now, **kw)` | Grounded answer for authorised party; records `JOURNAL_ACCESS` on chain (hash only). |
| `verify_answer(question, answer, fetch_entry, relevance, ...)` | Re-checks an answer against the journal: quotations exact, sentence boundaries, order, relevance, coverage. |
| `wish(pj, signer, wish_id, kind, item, recipient, note, assurance, revoked)` | Creates/updates a signed wish entry (private, encrypted). |
| `witness(pj, wish_record_sha, witness_signer)` | Adds a witness signature to a wish. |
| `statement_of_wishes(pj, signer, now)` | Exports all current wishes with signatures, witnesses, chain positions, Merkle proofs, packet signature. |
| `verify_statement(packet)` | Verifies a statement packet from the packet alone; returns list of problems (empty = valid). |
| `grounded.ground(question, units, relevance, min_score, coverage_min, max_units)` | Core grounding algorithm: whole units, owner-only, relevance threshold, coverage, written order, no additions. |
| `grounded.verify_answer(...)` | Independent verification of a grounded answer. |
| `crypto.seal/open_` | AES-256-GCM with AAD binding (position + prev hash). |
| `crypto.wrap_for/unwrap` | X25519 key agreement + HKDF-SHA256 + AES-GCM for key delivery. |
| `crypto.split/combine` | Shamir k-of-n with check hash (from vega-superproof-sdk). |
| `crypto.Signer/verify` | Ed25519 signatures over canonical JSON with domain tags. |
| `merkle.root/proof/verify` | RFC 6962 Merkle tree (leaf prefix 0x00, node prefix 0x01). |

---

## What it cannot do

- The journal's cryptography is plain Python with no independent security review; do not protect real secrets with it before an expert review.
- "Answers only" is enforced by the answering software's rules, not by mathematics; whoever controls that software at that moment could read everything.
- Revoking a `full` grant cannot unsee what the grantee already read; revocation stops future access only.
- The default word-overlap matcher is weak and refuses rather than guesses; a better matcher can be supplied but the grounding rules still hold.
- The times are the machine's clock; anchor the root outside it (e.g., a public timestamp) if the date must be provable to someone who does not trust the machine.
- A statement of wishes is evidence, NOT a will; whether a court gives informal writings any weight depends on the place and the facts, and no jurisdiction has been checked. Nothing here is legal advice.
- The journal does not defend against a compromised operating system, a stolen human key, or a bypass path that was never wired through the gate.
- The legacy policy's death declaration rests on the executors' honesty; choose them and the threshold carefully.
- External anchoring of the journal root, a real semantic relevance matcher, and speech-to-text for video are left to the caller.
- How a death is verified in the real world beyond k executors signing is a legal and procedural matter this code does not settle.

---

## Platform support

| Platform | Support |
|----------|---------|
| Windows (CPython 3.10+) | Full — pure Python, no POSIX-only code |
| macOS (CPython 3.10+) | Full — pure Python, no POSIX-only code |
| Linux (CPython 3.10+) | Full — pure Python, no POSIX-only code |
| Android | No native .apk build. The SDK is pure Python and can run inside a Python runtime on Android (Termux) where that runtime supports its dependencies. |
| iOS | No native .ipa build. The SDK is pure Python and can run inside a Python runtime on Apple platforms (BeeWare/Kivy) where that runtime supports its dependencies. |
| Hardware-dependent (GPU/TPM/HSM) | None required; designed for software-only operation. |

---

## Standalone & unified install

### Standalone
```bash
pip install -e .
```
Installs with zero family dependencies beyond the declared `vega-custody-sdk` and `vega-superproof-sdk` (both public SDKs at layer 0 and 2). The journal imports `vega_custody.dag.dag` for the hash chain and `vega_superproof.seal.keysplit` for Shamir sharing. It installs and runs alone with no other family SDKs.

### Unified
Registered in vega-umbrella-sdk's registry as layer 0 (record). The registry entry verbatim:
```python
"vega-journal-sdk": {"layer": 0, "concern": "record", "requires": ["vega-custody-sdk", "vega-superproof-sdk"]}
```
Dependencies point down layers only (custody at layer 0, superproof at layer 2); the umbrella resolves inter-SDK wiring.

> **One family, one organism:** every SDK owns exactly one concern and uses the owner of every other concern instead of growing its own copy.

---

## Diagnostic control surface

- **CLI entry points:** None published (no `console_scripts` in pyproject.toml).
- **Status/introspection:** `journal.verify()` → (bool, problems), `journal.root()`, `journal.head`, `journal.inclusion_proof(record_hash)`, `private_journal.status(now)`, `private_journal.verify_answer(...)`.
- **Log surfaces:** Every record written produces a `JOURNAL_RECORD` event on the DAG; every `ask()` produces a `JOURNAL_ACCESS` event (hash only: party reference, role, answerable, unit count, question hash). No plaintext logs.
- **Exit codes / fail-closed indicators:** All validation failures raise `JournalRefused` (or `Locked` for missing keys); crypto failures raise `CryptoRefused`; chain failures raise `DagError` wrapped in `JournalRefused`. No operation succeeds on error.
- **Environment variables honored:** None.
- **Visual UI:** A diagnostic UI design for this layer exists in the Vega OS interface program; it is not shipped with this package.

---

## Fail-closed constraints & custom constraints

### Fail-closed constraint points (module + function)

1. `journal.Journal._load` — refuses edited, deleted, reordered, cut, or half-written journal files (chain break → `JournalRefused`).
2. `journal.Journal._write` — writes to DAG first; if chain write fails, nothing recorded (`JournalRefused`).
3. `journal.Journal._entry` — refuses invalid speaker, kind, empty/oversized/NUL text, invalid session, credential-shaped text (redacted + hash kept).
4. `journal.Journal.answer` — refuses answers that don't name a valid question (`JournalRefused`).
5. `journal.Journal.idea` — refuses anchoring in redacted entries, duplicate names, quotes outside entry bounds (`JournalRefused`).
6. `journal.Journal.derive` — refuses cycles and self-edges (`JournalRefused`); cycle detection is the enforcement.
7. `journal.Journal.conception_receipt` — refuses if no anchor for the requested origin (`JournalRefused`); a model's suggestion is never credited to the owner.
8. `journal.verify_receipt` — returns `False` on any Merkle path mismatch, quote mismatch, or malformed packet; never raises.
9. `private.PrivateJournal._entry_key` — returns `None` if decryption fails (wrong key, wrong place, altered data); caller raises `Locked`.
10. `private.PrivateJournal._plain_of` — raises `Locked` if no key; raises `JournalRefused` if decryption fails (tamper detected).
11. `private.PrivateJournal._apply_extra` — every policy record (grant, revoke, legacy, death, alive, witness) verified against owner's signature; invalid records increment `rejected` and are ignored.
12. `private.PrivateJournal.grant` — requires owner's master key, valid signer, valid keys, future expiry; refuses otherwise (`Locked`/`JournalRefused`).
13. `private.PrivateJournal.revoke` — only owner with master key can revoke active grants.
14. `private.PrivateJournal.set_legacy` — validates executors (2-12, threshold 2+), cooling_days (1-365), unique beneficiary names, valid modes/scopes; requires master key.
15. `private.PrivateJournal.declare_death` — requires k valid executor signatures on identical declaration for current legacy version; refuses otherwise.
16. `private.PrivateJournal.alive` — only during cooling-off; only owner with master key.
17. `private.PrivateJournal.release` — only when `status == "legacy_effective"`; requires threshold valid shares that open the sealed service key; on failure raises `JournalRefused`, state unchanged.
18. `private.PrivateJournal._authority` — deny-by-default: owner needs master key; grantee needs active unrevoked unexpired grant and running service; beneficiary needs effective legacy, release, and matching identity; otherwise `JournalRefused`/`Locked`.
19. `private.PrivateJournal.ask` — records `JOURNAL_ACCESS` on chain BEFORE returning answer; if chain write fails, answer is not returned (`JournalRefused`).
20. `grounded.ground` — refuses questions with no content words, invalid params; returns `answerable: False` if no unit meets `min_score` or coverage < `coverage_min`; never guesses.
21. `grounded.verify_answer` — returns `False` on any rule violation (non-owner speaker, redacted, not whole sentence, wrong offsets, wrong order, low relevance, coverage drop, tampered media); never raises.
22. `last_rites.wish` — only owner's signer; validates wish_id, kind, field lengths, assurance 0-4; refuses otherwise.
23. `last_rites.verify_statement` — returns problems on any signature, hash, proof, witness, notice, or field mismatch; never raises.

### Custom constraints

This version publishes no user-defined constraint hooks; constraints are fixed by the module and the jurisdiction floor. The governing rule (if hooks are added in a future version):

> **User-defined constraints may be STRICTER than the legal minimum for the applicable jurisdiction, never looser. Jurisdictional legal minimums are defined by the jurisdiction registry (vega-jurisdiction-sdk); a custom constraint that would drop below a registered minimum is rejected at the gate.**

---

## Tests

69 tests total:
- `tests/redteam_1_journal.py`: 24 tests (verbatim storage, chain integrity, tampering detection, search, thought genome, origin, receipts, Merkle proofs)
- `tests/redteam_2_private.py`: 45 tests (encryption at rest, locked open, ciphertext binding, grants, grounded answers, legacy policy, last-rites)

Run:
```bash
source SDK_FAMILY/env_family.sh
py -3.12 tests/redteam_1_journal.py
py -3.12 tests/redteam_2_private.py
```

Mutation tests (each rule removed must make tests fail):
```bash
py -3.12 tests/mutations_journal.py
py -3.12 tests/mutations_private.py
```

---

## Status & honesty

Reference implementation, work in progress, not independently security-reviewed, crypto not expert-reviewed. The modules marked BUILT in STATUS.md are implemented and tested; DESIGNED ONLY items (external anchoring, semantic matcher, speech-to-text, real-world death verification) are not in this code. This kit details one branch of a broader filed architecture. The remaining branches are the subject of filed disclosures and are outside the scope of this repository.
