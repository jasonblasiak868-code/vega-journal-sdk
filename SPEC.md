# vega-journal-sdk — Specification

Spec v1.0 — 2026-10-19 — describes the published reference implementation as tested; where this document and the source disagree, the source wins.

---

## 1. Purpose and scope

This specification defines the behaviour of the vega-journal-sdk reference implementation (version 0.1.0). It covers:

- The base journal: a verbatim, append-only, hash-chained record of entries with a thought-genome map (ideas, anchors, edges) and Merkle receipts.
- The private journal: encryption at rest, lifetime grants (full and answers-only), a legacy policy with k-of-n executors and cooling-off, and last-rites wishes.
- The grounded answering engine: answers composed only of whole sentences or transcript segments from the owner's own words, each relevant on its own, in written order, with nothing added.
- Cryptographic primitives: AES-256-GCM with AAD binding, X25519 key wrapping, Shamir secret sharing, Ed25519 signatures, RFC 6962 Merkle trees.

Out of scope: external timestamp anchoring of the journal root, semantic relevance matchers (the default is word overlap), speech-to-text for video, real-world death verification beyond k executor signatures, legal validity of wishes, and any deployment or operational concerns.

---

## 2. Vocabulary

| Term | Definition |
|------|------------|
| **Entry** | A line of conversation: speaker (owner, model, observer, system), session, text, kind (note, question, answer, wish). An answer names the question it answers. |
| **Idea** | A named concept with its first anchor: an exact quotation from an entry (start/end offsets, quote hash) and its origin (who said it). |
| **Anchor** | A later appearance of an existing idea in another entry; records the quotation, entry, and time. |
| **Edge** | A "grew from" relationship between two ideas (child -> parent), recorded in an entry; cycles are refused. |
| **Commitment** | In this SDK: the owner's signed wish or grant; more generally, a single-use human-signed authorisation (from governance-jacket). |
| **Gate** | A check that refuses unless a valid commitment exists for the exact action (e.g., ask() requires _authority() to pass). |
| **Receipt** | conception_receipt: the earliest anchor of an idea by a given origin, with the journal root and a Merkle inclusion proof. |
| **Grant** | A signed policy record giving a grantee access: mode full (keys wrapped to grantee's box key) or answers_only (no keys, ask only). Scoped by sessions, tags, time, or all. |
| **Legacy policy** | Owner-defined post-death release: executors (k of n), cooling-off period, beneficiaries with per-beneficiary scope and mode. |
| **Legacy key (L)** | A random key split among executors via Shamir sharing; unseals the service key and beneficiary bundles. |
| **Service key (S)** | A key held by the answering service; wraps entry keys for answers_only grants and legacy beneficiaries. |
| **Master key (M)** | The owner's 32-byte key; wraps every entry key and the service key at initialisation. |
| **Box key** | An X25519 key pair; the public key is used to wrap secrets for delivery, the private key unwraps them. |
| **Merkle root** | The root hash of the RFC 6962 Merkle tree over all record hashes in the journal. |
| **Inclusion proof** | A Merkle path from a leaf (record hash) to the root, verifiable without the full journal. |
| **Grounded answer** | An answer composed of whole units (sentences or transcript segments) from the owner's unredacted entries, each meeting min_score, collectively meeting coverage_min, in written order, with nothing added. |
| **JournalRefused** | The exception raised when any validation, authorisation, or integrity check fails — the operation does not proceed. |
| **Locked** | The exception raised when the owner's master key is required but not provided. |

---

## 3. Components

### 3.1 journal.py — Journal (base)

**Role:** The append-only, hash-chained record of entries, ideas, anchors, edges, with search, first-use, lineage, receipts, and Merkle proofs.

**Public interface:**
- Journal(path, dag, clock=time.time) — constructor; loads and verifies existing file.
- verify() -> (bool, list[str]) — re-reads file, re-checks every hash, compares with DAG's JOURNAL_RECORD events.
- add(speaker, text, session, kind) — appends a note entry.
- question(speaker, text, session) — appends a question entry.
- answer(question_id, speaker, text, session) — appends an answer entry naming a question.
- get(entry_id) — returns the entry record.
- pairs() — returns list of (question, answer) tuples.
- unanswered() — returns questions with no answer.
- search(query, speaker, limit) — word-overlap ranked search.
- first_use(term, speaker) — earliest entry containing all query words.
- idea(name, entry_id, start, end) — creates an idea anchored to a quotation.
- anchor(name, entry_id, start, end) — adds a later anchor to an existing idea.
- derive(child, parent, entry_id) — records a "grew from" edge; refuses cycles and self-edges.
- first_anchor(name, origin) — earliest anchor for an idea, optionally filtered by origin.
- lineage(name) — ancestors nearest first, each with earliest anchor time and origin.
- root() — Merkle root of all record hashes.
- inclusion_proof(record_hash) — {index, size, path} for a record.
- conception_receipt(name, origin="owner") — earliest anchor by origin, with Merkle proof; refuses if origin never said it.
- verify_receipt(receipt, quote_text) — static verifier: checks Merkle path and optional quote hash.

**Behaviour on success:** Returns the created record; chain and file stay consistent; verify() returns (True, []).

**Behaviour on failure:** Raises JournalRefused with a descriptive message; no record is written; file unchanged.

**Invariants:**
- Every record's prev equals the previous record's sha256; positions (i) run 0, 1, 2...
- A record's sha256 covers all fields except itself; tampering breaks the chain.
- Credential-shaped text is never written; replaced with a marker, original hash kept in original_sha256.
- Ideas are unique by case-insensitive name; anchors only added to existing ideas.
- Edges form a DAG; cycles and self-edges refused.
- Origin of an idea is the speaker of its earliest anchor; a model's suggestion is never credited to the owner.
- conception_receipt refuses if the requested origin has no anchor for that idea.
- Merkle tree uses RFC 6962: leaf = H(0x00 || h), node = H(0x01 || left || right), split at largest power of two < n.

### 3.2 private.py — PrivateJournal (encrypted, grants, legacy, last-rites)

**Role:** Extends Journal with encryption at rest, access control via grants and legacy policy, and last-rites wishes.

**Public interface (inherited + new):**
- PrivateJournal(path, dag, owner_sign_public, master_key=None, clock=time.time) — master_key required for owner operations; None for locked open.
- initialise(signer) — writes init record: binds owner identity, wraps service key under master key. Requires master key and matching signer.
- read(entry_id) -> {'text', 'segments'} — owner-only decryption.
- unlock_for_search() — decrypts all entries into memory, builds search index (never written to disk).
- grant(grantee_sign, grantee_box, mode, scope, signer, expires_at) -> grant_id — creates signed grant record; full mode wraps entry keys to grantee's box key.
- share_new(grant_id, signer) — wraps keys for new entries in grant's scope; needs grant key in memory.
- revoke(grant_id, signer) — marks grant revoked.
- grantee_open(grant_id, box) — full grantee decrypts their entries using their box private key.
- set_legacy(executors, threshold, cooling_days, beneficiaries, signer) — creates legacy policy: splits legacy key L, seals service key and beneficiary bundles under L.
- prepare_death(evidence_sha256) -> declaration body — builds the declaration executors sign.
- declare_death(body, sigs) -> death_id — verifies k valid executor signatures on identical declaration for current legacy version.
- alive(death_id, signer) — owner cancels a declaration during cooling-off.
- status(now) -> "living" | "death_declared_cooling" | "legacy_effective".
- release(shares, now) -> bool — combines executor shares, recovers L, opens service key, rebuilds index, records release.
- beneficiary_open(name, box) — full beneficiary decrypts their bundle after release.
- ask(party, question, relevance, now, **kw) -> grounded answer — for authorised party; records JOURNAL_ACCESS on chain (hash only).
- verify_answer(question, answer, fetch_entry, relevance, ...) -> bool — independent verification of a grounded answer.

**Behaviour on success:** Returns the created record or requested data; chain and file stay consistent; verify() returns (True, []).

**Behaviour on failure:** Raises JournalRefused (validation, authorisation, integrity) or Locked (master key required); no state change on failure.

**Invariants:**
- Every entry encrypted with a unique key; key wrapped to master key (M) and service key (S); AAD binds position + prev hash.
- Ciphertext cannot be moved to another position or edited (AAD mismatch on decrypt).
- All policy records (grant, revoke, legacy, death, alive, witness) verified against owner's Ed25519 signature; invalid records increment rejected and are ignored.
- full grants deliver entry keys wrapped to grantee's box key; answers_only grants deliver no keys.
- Grants expire at expires_at; revoked grants are inert.
- Legacy policy versions increment by 1; skipping versions refused.
- Death declaration requires k-of-n executor signatures on identical body for current legacy version.
- Cooling-off period enforced: owner can cancel only before cooling_until; after, alive refused.
- Release only when status == "legacy_effective" and threshold valid shares open the sealed service key.
- _authority(party, now) deny-by-default: owner needs M; grantee needs active grant + running service; beneficiary needs effective legacy + release + matching identity.
- Every ask() records JOURNAL_ACCESS on chain BEFORE returning answer; if chain write fails, answer not returned.
- Wishes are signed entries (kind wish) with payload_sha256, assurance (0-4), owner signature; witnesses add separate witness records with their signatures.
- statement_of_wishes exports all current (non-revoked) wishes with signatures, witnesses, chain positions, Merkle proofs, and a packet signature.
- verify_statement checks packet alone: export signature, notice text, each wish's text hash, owner signature, Merkle inclusion, witness signatures, status consistency, unique wish IDs.

### 3.3 grounded.py — Grounded answering engine

**Role:** Produces and verifies answers composed only of whole units from the owner's own words.

**Public interface:**
- lexical_relevance(question, unit) -> float — default relevance: word overlap (deterministic, weak).
- split_units(text) -> [(start, end, sentence)] — complete sentences with offsets.
- candidates(entries) -> list of units — flattens entries to units in journal order; only owner, unredacted.
- ground(question, units, relevance, min_score, coverage_min, max_units) -> answer dict:
  - answerable: bool, question_terms, coverage, segments (each with entry, start, end, text, at, score, media), reason.
- render(answer) -> str — quotations with dates, joined by newlines; nothing else added.
- verify_answer(question, answer, fetch_entry, relevance, min_score, coverage_min) -> bool — re-checks every rule; never raises.

**Behaviour on success:** Returns answer with answerable: True if coverage >= coverage_min (or a unit scores >= 0.9), else answerable: False with reason.

**Behaviour on failure:** Raises GroundedRefused for invalid params (empty question, min_score/coverage_min not in (0,1], max_units not in [1,50], relevance returns non-number).

**Invariants (tested):**
- Every unit is a complete sentence (text) or complete transcript segment (media).
- Every unit scores >= min_score on its own.
- Only owner's unredacted words are used.
- Units from multiple entries allowed if each adds coverage or scores >= 0.9.
- Units stay in written order (entry position, then offset).
- Nothing added: no paraphrase, filler, synthetic voice, or edited media clips.
- If coverage < coverage_min and no unit >= 0.9, returns answerable: False.
- verify_answer returns False on any violation: non-owner speaker, redacted, not whole sentence, wrong offsets, wrong order, low relevance, coverage drop, tampered media, malformed input.

### 3.4 last_rites.py — Last-rites wishes

**Role:** Owner-signed wishes with assurance level, optional witnesses, and verifiable export.

**Public interface:**
- wish(pj, signer, wish_id, kind, item, recipient, note, assurance, revoked) — creates/updates a wish entry (private, encrypted). Later wish with same ID supersedes; history stays in chain.
- witness(pj, wish_record_sha, witness_signer) — adds a witness signature to a wish.
- statement_of_wishes(pj, signer, now) — exports packet: notice, owner_sign, exported_at, journal_root, journal_size, chain_head, wishes (each with payload_text, payload_sha256, record_sha256, position, recorded_at, owner_sig, assurance, tags, witnesses, status, proof), export_sig.
- verify_statement(packet) -> list[str] — verifies from packet alone; empty list = valid.

**Behaviour on success:** Returns the created record or packet.

**Behaviour on failure:** Raises JournalRefused for invalid params, wrong signer, malformed input.

**Invariants:**
- wish_id format: lowercase alphanumeric, underscore, hyphen, 2-40 chars.
- kind in {property, digital_assets, funeral, care, message, other}.
- Field lengths enforced: item 1-500, recipient 0-200, note 0-2000.
- Assurance 0-4 or None (identity level from identity SDK).
- Only owner's signer can create a wish.
- Revoked wishes excluded from current_wishes and statement_of_wishes.
- Witness signatures verified against wish's payload_sha256; status witnessed iff >= 2 valid witnesses.
- statement_of_wishes packet signed by owner; verify_statement checks export sig, notice, each wish's text hash, owner sig, Merkle inclusion, witness sigs, status, unique IDs.
- NOTICE text is fixed: "This is a statement of the owner's wishes... NOT a will... show this to an attorney."

### 3.5 crypto.py — Cryptographic primitives

**Role:** AES-256-GCM sealing, X25519 key wrapping, Shamir splitting, Ed25519 signing, HMAC.

**Public interface:**
- new_key() -> 32 random bytes.
- seal(key, plaintext, aad) -> (nonce, ciphertext).
- open_(key, nonce, ct, aad) -> plaintext; raises CryptoRefused on failure.
- KeyPair() — generates X25519 key pair; .public (32 bytes), .unwrap(blob) -> secret.
- wrap_for(public, secret) -> blob (ephemeral_pub + nonce + ct).
- split(secret, k, n) -> [(x, share_bytes)], check — Shamir k-of-n with check hash (from vega-superproof-sdk).
- combine(shares, check, k, n) -> secret; raises CryptoRefused on failure.
- canonical(obj) -> canonical JSON bytes (sorted keys, no whitespace, no NaN).
- Signer() — generates Ed25519 key pair; .public (32 bytes), .sign(tag, body) -> hex signature over VEGA-JOURNAL-SIG-1|tag|canonical(body).
- verify(public, tag, body, sig_hex) -> bool.
- mac(key, data) -> HMAC-SHA256 hex over VEGA-JOURNAL-MAC-1|data.

**Invariants:**
- All keys 32 bytes; nonces 12 bytes (AES-GCM).
- AAD binds ciphertext to its position in the journal (entry index + prev hash).
- Key wrapping uses ephemeral X25519 + HKDF-SHA256 + AES-GCM; only recipient's private key opens.
- Shamir shares: 2 <= k <= n <= 16; fewer than k shares reveal nothing; check hash prevents mixing shares from different splits.
- Signatures domain-separated by tag; canonical JSON prevents ambiguity.

### 3.6 merkle.py — Merkle tree (RFC 6962)

**Role:** Merkle root, inclusion proofs, verification over record hashes.

**Public interface:**
- root(hashes) -> hex root.
- proof(hashes, index) -> [(side, sibling_hash_hex)] from leaf up.
- verify(root_hex, leaf_hex, path) -> bool.

**Invariants:**
- Leaf hash = SHA256(0x00 || leaf_bytes).
- Node hash = SHA256(0x01 || left || right).
- Tree splits at largest power of two < n.
- verify returns False on any malformed input; never raises.

---

## 4. Guarantees and non-guarantees

### Guarantees (with module + test)

| Guarantee | Module | Test |
|-----------|--------|------|
| Verbatim storage: text written exactly as given (except credential redaction) | journal | redteam_1_journal.py::Entries::test_text_is_kept_verbatim... |
| Hash chain integrity: any edit/delete/reorder/cut detected on load | journal | redteam_1_journal.py::Chain::test_editing_deleting_reordering... |
| DAG cross-check: rewritten but internally consistent chain fails against DAG | journal | redteam_1_journal.py::Chain::test_a_rewritten_chain... |
| Credentials never written to journal file or DAG | journal | redteam_1_journal.py::Entries::test_a_credential_is_never_written... |
| Ideas anchored to exact quotations; quote hash verified | journal | redteam_1_journal.py::Genome::test_an_idea_is_anchored... |
| Origin credited to actual speaker; model never credited as owner | journal | redteam_1_journal.py::Genome::test_origin_is_who_said_it... |
| Cycles and self-edges refused | journal | redteam_1_journal.py::Genome::test_ideas_grow_from_ideas... |
| Conception receipt includes earliest anchor by origin, Merkle proof | journal | redteam_1_journal.py::Receipts::test_a_receipt_checks_out... |
| Old receipts stay valid against their own root after journal grows | journal | redteam_1_journal.py::Receipts::test_an_old_receipt_stays_valid... |
| Encryption at rest: no plaintext in journal file | private | redteam_2_private.py::Encryption::test_the_file_holds_no_plaintext... |
| Ciphertext bound to position: moving/editing ciphertext fails decrypt | private | redteam_2_private.py::Encryption::test_a_ciphertext_cannot_be_moved... |
| Locked open: chain verifies, entries unreadable without keys | private | redteam_2_private.py::Encryption::test_the_file_holds_no_plaintext... |
| Full grants deliver exactly scoped entry keys to grantee's box key | private | redteam_2_private.py::Grants::test_a_full_grant_delivers... |
| Answers-only grants carry no keys; grantee asks grounded questions | private | redteam_2_private.py::Grants::test_an_answers_only_grant_carries_no_keys |
| Grants expire and can be revoked; both stop access | private | redteam_2_private.py::Grants::test_revocation_and_expiry_stop_access |
| Forged/altered policy records ignored and counted in rejected | private | redteam_2_private.py::Grants::test_forged_or_altered_policy_records... |
| Legacy policy: k-of-n executors, version increment, cooling-off | private | redteam_2_private.py::Legacy::test_a_death_needs_k_executors... |
| Owner can cancel during cooling-off; not after | private | redteam_2_private.py::Legacy::test_the_owner_can_cancel... |
| Release requires effective legacy + threshold valid shares | private | redteam_2_private.py::Legacy::test_release_needs_an_effective... |
| Beneficiaries get exactly their scoped access; executors cannot read | private | redteam_2_private.py::Legacy::test_after_release_each_beneficiary... |
| Grounded answers: whole units, owner-only, relevance, coverage, order, no additions | grounded | redteam_2_private.py::GroundedAnswers::test_the_owner_gets_quotations... |
| Every ask recorded on chain (hash only); chain failure blocks answer | private | redteam_2_private.py::GroundedAnswers::test_every_ask_is_recorded... |
| Answer verification catches all alterations | grounded | redteam_2_private.py::GroundedAnswers::test_every_alteration... |
| Wishes signed, versioned, withdrawable; witnesses add signatures | last_rites | redteam_2_private.py::LastRites::test_wishes_are_signed_versioned... |
| Statement verifies from packet alone; catches every change | last_rites | redteam_2_private.py::LastRites::test_the_statement_verifies... |

### Non-guarantees

| Non-guarantee | Explanation |
|---------------|-------------|
| Cryptography independently reviewed | Plain Python with cryptography library primitives; no expert audit. |
| Answers-only enforced by mathematics | Enforced by answering software rules; whoever controls the software could read everything. |
| Revocation unsees data | Full grantee who already received keys may have kept what they read. |
| Default matcher understands semantics | Word overlap only; misses paraphrase; a better matcher can be supplied. |
| Machine clock is trustworthy | Anchor root externally (e.g., public timestamp) if date must be provable. |
| Wishes are legally valid wills | Explicitly NOT a will; weight depends on jurisdiction; not legal advice. |
| Defends against compromised OS/stolen key/bypass | Threat model assumes OS, clock, disk not controlled by attacker; keys not stolen. |
| Death verified beyond executor signatures | Real-world death verification is legal/procedural; not in code. |
| External anchoring, semantic matcher, STT included | Left to the caller (DESIGNED ONLY per STATUS.md). |

---

## 5. Failure modes (from tests)

| Failure mode | What happens | Test |
|--------------|--------------|------|
| Tampered journal file (edit/delete/reorder/cut/half-line) | JournalRefused on load; verify() returns (False, problems) | redteam_1_journal.py::Chain::test_editing_deleting_reordering... |
| Splice from another journal | JournalRefused on load (prev hashes don't match) | redteam_1_journal.py::Chain::test_a_splice_from_another_journal... |
| Renumbered records | JournalRefused on load (positions don't match) | redteam_1_journal.py::Chain::test_a_splice_from_another_journal... |
| Rewritten chain consistent internally but not with DAG | verify() returns (False, problems): 2 mismatches (file vs chain, chain vs file) | redteam_1_journal.py::Chain::test_a_rewritten_chain... |
| Missing record in file but present in DAG | verify() reports "in the chain but not in the file" | redteam_1_journal.py::Chain::test_a_record_in_the_chain... |
| Clock runs backwards | JournalRefused on write | redteam_1_journal.py::Chain::test_the_clock_cannot_run_backwards... |
| Chain write fails (disk full) | JournalRefused; nothing recorded; file unchanged | redteam_1_journal.py::Chain::test_if_the_chain_cannot_be_written... |
| Credential in entry text | Redacted to marker; original hash kept; cannot anchor idea | redteam_1_journal.py::Entries::test_a_credential_is_never_written... |
| Answer names non-question or missing question | JournalRefused | redteam_1_journal.py::Entries::test_questions_and_answers |
| Anchor quote outside entry bounds | JournalRefused | redteam_1_journal.py::Genome::test_an_idea_is_anchored... |
| Duplicate idea name | JournalRefused | redteam_1_journal.py::Genome::test_an_idea_is_anchored... |
| Cycle in idea edges | JournalRefused | redteam_1_journal.py::Genome::test_ideas_grow_from_ideas... |
| Self-edge | JournalRefused | redteam_1_journal.py::Genome::test_ideas_grow_from_ideas... |
| Conception receipt for origin that never said it | JournalRefused | redteam_1_journal.py::Genome::test_origin_is_who_said_it... |
| Receipt quote altered | verify_receipt returns False | redteam_1_journal.py::Receipts::test_a_receipt_checks_out... |
| Receipt Merkle path altered | verify_receipt returns False | redteam_1_journal.py::Receipts::test_a_receipt_checks_out... |
| Ciphertext moved to another position | Decrypt fails -> JournalRefused on unlock_for_search | redteam_2_private.py::Encryption::test_a_ciphertext_cannot_be_moved... |
| Wrong master key on open | Decrypt fails -> exception | redteam_2_private.py::Encryption::test_the_file_holds_no_plaintext... |
| Forged grant/revoke/legacy/death/alive/witness record | Ignored; rejected incremented | redteam_2_private.py::Grants::test_forged_or_altered_policy_records... |
| Death declaration: < k signatures / wrong body / wrong version / stranger sig | JournalRefused | redteam_2_private.py::Legacy::test_a_death_needs_k_executors... |
| Alive after cooling-off | JournalRefused | redteam_2_private.py::Legacy::test_the_owner_can_cancel... |
| Release: not effective / < threshold shares / wrong shares / duplicate shares | JournalRefused; state unchanged | redteam_2_private.py::Legacy::test_release_needs_an_effective... |
| Beneficiary: wrong key / wrong mode / not released / stranger | JournalRefused | redteam_2_private.py::Legacy::test_after_release_each_beneficiary... |
| Executor tries to read as beneficiary | JournalRefused | redteam_2_private.py::Legacy::test_executors_cannot_read... |
| Grounded answer: no units meet min_score | answerable: False, reason "the journal does not answer this question" | redteam_2_private.py::GroundedAnswers::test_no_answer_if... |
| Grounded answer: coverage < coverage_min | answerable: False, reason "what the journal says covers only part" | redteam_2_private.py::GroundedAnswers::test_no_answer_if... |
| Grounded answer: model/observer/redacted words | Never used; only owner unredacted | redteam_2_private.py::GroundedAnswers::test_only_the_owners_own... |
| Grounded answer: wishes returned by ordinary questions | Excluded (kind == wish filtered) | redteam_2_private.py::GroundedAnswers::test_wishes_are_not_returned... |
| Media answer: clip trimmed to different cut | verify_answer returns False | redteam_2_private.py::GroundedAnswers::test_video_answers... |
| Answer altered: text, offsets, order, entry, time, segments dropped | verify_answer returns False | redteam_2_private.py::GroundedAnswers::test_every_alteration... |
| Weak unit that would complete coverage but scores < min_score | Excluded; answer refused | redteam_2_private.py::GroundedAnswers::test_a_weak_unit_is_not_let_in... |
| Units shown in score order instead of written order | verify_answer returns False (order check) | redteam_2_private.py::GroundedAnswers::test_pieces_are_shown... |
| Unit that adds no new coverage | Excluded | redteam_2_private.py::GroundedAnswers::test_a_unit_that_adds_nothing... |
| Bad relevance function (returns str, NaN, bool, None) | GroundedRefused | redteam_2_private.py::GroundedAnswers::test_a_better_matcher... |
| Wish: invalid ID, kind, field lengths, assurance, non-owner signer | JournalRefused | redteam_2_private.py::LastRites::test_wishes_are_signed_versioned... |
| Forged wish record (bad signature/hash) | Not counted in wish_records | redteam_2_private.py::LastRites::test_a_forged_wish_record... |
| Witness: bad signature | Not counted; rejected incremented | redteam_2_private.py::LastRites::test_witnesses_count_only... |
| Statement: any field altered | verify_statement returns non-empty problems | redteam_2_private.py::LastRites::test_the_statement_verifies... |

---

## 6. Dependencies and layer rules

**Registry entry (verbatim from vega-umbrella-sdk):**
```python
"vega-journal-sdk": {"layer": 0, "concern": "record", "requires": ["vega-custody-sdk", "vega-superproof-sdk"]}
```

**Dependencies:**
- vega-custody-sdk (layer 0, record) — provides Dag, contains_credential, hash-chained ledger for JOURNAL_RECORD and JOURNAL_ACCESS events.
- vega-superproof-sdk (layer 2, seal) — provides keysplit.split_checked / combine_checked for Shamir sharing of the legacy key.

**Layer rules:** Dependencies point down layers only (custody at layer 0, superproof at layer 2). No upward or sideways dependencies. This SDK owns the "record" concern at layer 0.

---

## 7. Conformance

A third party can verify conformance by running the test suite:

```bash
source SDK_FAMILY/env_family.sh
py -3.12 tests/redteam_1_journal.py
py -3.12 tests/redteam_2_private.py
```

**What passing means:** All 74 tests pass; the reference implementation behaves as specified in this document for the tested scenarios.

**What passing does NOT mean:**
- The cryptography has been independently reviewed.
- The implementation is hardened for production use.
- External anchoring, semantic matching, speech-to-text, or real-world death verification are provided.
- The legal validity of wishes or legacy policies is established in any jurisdiction.
- The code is free of vulnerabilities not covered by the test suite.
