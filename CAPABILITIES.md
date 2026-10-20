# vega-journal-sdk — Capabilities

Deep capability inventory per OWNER_DIRECTIVE_20261019.md and TEMPLATE.md. Each capability lists: what it does, why a policy-or-prompt-level approach structurally cannot provide it, where enforced in this repo's code, which test demonstrates it, and the honest limit.

---

## Capability inventory

### 1. Verbatim, append-only, hash-chained journal

| Aspect | Detail |
|--------|--------|
| **Capability** | Every entry written verbatim (except credential redaction) to a JSON-lines file where each record hashes the previous; tampering (edit, delete, reorder, cut, half-line) detected on load. |
| **Why policy/prompt fails** | A prompt says "don't edit the log." The model or a compromised process can edit the file directly. No cryptographic binding to the past without the chain. |
| **Where enforced** | `journal.py`: `_write()` (hashes prev, writes to Dag first), `_load()` (verifies every `prev`, `i`, `sha256`), `verify()` (re-reads, re-checks, compares with Dag). |
| **Test** | `redteam_1_journal.py::Chain::test_editing_deleting_reordering_or_cutting_is_caught_and_located`, `test_a_splice_from_another_journal`, `test_a_rewritten_chain_that_is_internally_consistent_still_fails_against_the_dag`, `test_if_the_chain_cannot_be_written_nothing_is_recorded`. |
| **Honest limit** | The machine clock can be manipulated; anchor the root externally (public timestamp) if date must be provable to a non-trusting party. |

---

### 2. Credential redaction with hash preservation

| Aspect | Detail |
|--------|--------|
| **Capability** | Credential-shaped values (API keys, JWTs, private keys, passwords, bearer tokens) are never written to the journal or Dag; replaced with a marker; original SHA-256 kept in `original_sha256`. |
| **Why policy/prompt fails** | A prompt says "don't log secrets." The model may still emit them; a compromised process can write them. The redaction must be mandatory and enforced at write time. |
| **Where enforced** | `journal.py`: `_entry()` calls `contains_credential()` (from vega-custody-sdk) before write; if true, writes `MARK` and keeps hash. `_load()` refuses anchoring ideas in redacted entries. |
| **Test** | `redteam_1_journal.py::Entries::test_a_credential_is_never_written_but_the_original_is_vouched_for_by_its_hash`. |
| **Honest limit** | The credential detector uses regex patterns; novel credential formats may slip through. The hash of the original is kept — if the journal file is stolen, an attacker with the original text can confirm it was that credential. |

---

### 3. Thought-genome map: ideas, anchors, edges with origin

| Aspect | Detail |
|--------|--------|
| **Capability** | Named ideas anchored to exact quotations (start/end offsets, quote hash) with recorded origin (owner, model, observer, system). Later anchors add refinements. Edges record "grew from" relationships; cycles and self-edges refused. Lineage traces ancestors with earliest anchor time and origin. |
| **Why policy/prompt fails** | A prompt says "track where ideas came from." The model can hallucinate origins, reorder history, or claim a model's suggestion as the user's. The journal enforces: origin = speaker of earliest anchor; conception receipt refuses to credit model's words to owner. |
| **Where enforced** | `journal.py`: `idea()` (validates quote, records origin), `anchor()` (validates existing idea, records origin), `derive()` (cycle detection via stack walk), `first_anchor()` (earliest by journal position), `lineage()` (BFS up parents), `conception_receipt()` (refuses if requested origin has no anchor). |
| **Test** | `redteam_1_journal.py::Genome::test_an_idea_is_anchored_to_an_exact_quotation_and_the_quote_is_checked`, `test_origin_is_who_said_it_and_a_models_suggestion_is_never_credited_to_the_owner`, `test_ideas_grow_from_ideas_without_cycles`, `test_the_earliest_anchor_wins_even_if_it_was_added_last`. |
| **Honest limit** | Conception ≠ legal priority; the receipt proves the journal contained the quotation at that position, not that the owner invented it first. External anchoring needed for provable timestamps. |

---

### 4. Merkle receipts (conception receipts) verifiable by third parties

| Aspect | Detail |
|--------|--------|
| **Capability** | `conception_receipt(idea, origin)` returns: idea name, origin, recorded_at, entry hash, entry position, quote offsets, quote hash, journal root, journal size, chain head, Merkle inclusion proof. `verify_receipt()` checks Merkle path and optional quote hash from the receipt alone — no journal needed. |
| **Why policy/prompt fails** | A prompt says "give me a receipt." The model can fabricate one. A third party cannot verify a prompt-generated receipt without the full journal. Merkle proofs are mathematically verifiable without trusting the model or the vendor. |
| **Where enforced** | `journal.py`: `root()` (RFC 6962 Merkle root), `inclusion_proof()` (path from leaf to root), `conception_receipt()` (assembles receipt), `verify_receipt()` (static verifier, never raises). `merkle.py`: `root()`, `proof()`, `verify()` (leaf prefix 0x00, node prefix 0x01). |
| **Test** | `redteam_1_journal.py::Receipts::test_a_receipt_checks_out_and_catches_every_alteration`, `test_an_old_receipt_stays_valid_against_its_own_root_after_the_journal_grows`, `MerkleTests::test_every_leaf_of_every_size_proves_and_nothing_else_does`, `test_leaves_and_nodes_are_hashed_with_different_prefixes`. |
| **Honest limit** | Receipt proves inclusion in the journal at that root; does not prove the journal wasn't forked. The chain head and Dag cross-check mitigate this. |

---

### 5. Encryption at rest (owner-only by default)

| Aspect | Detail |
|--------|--------|
| **Capability** | Every entry encrypted with a unique AES-256-GCM key; entry key wrapped to master key (M) and service key (S); AAD binds ciphertext to position (entry index + prev hash). Without M, the journal is a chain of ciphertext — chain verifies, entries unreadable. |
| **Why policy/prompt fails** | A prompt says "encrypt the data." The model or process holds the key in memory and can leak it. Encryption must be structural: keys wrapped to keys the model never holds (M held only by owner; S held by answering service). |
| **Where enforced** | `private.py`: `_make_entry()` (generates entry key, seals payload, wraps to M and S), `_entry_key()` (unwraps from M or S), `_plain_of()` (decrypts, raises `Locked` if no key, `JournalRefused` if tamper), `unlock_for_search()` (decrypts all to memory, never writes plaintext to disk). |
| **Test** | `redteam_2_private.py::Encryption::test_the_file_holds_no_plaintext_and_a_locked_open_reads_nothing`, `test_search_works_for_the_owner_after_unlock_and_the_index_is_never_written`, `test_a_ciphertext_cannot_be_moved_to_another_place_or_edited`. |
| **Honest limit** | Plain Python cryptography with `cryptography` library primitives; no independent review. Master key in memory during owner operations. |

---

### 6. Lifetime grants: full and answers-only, scoped, expirable, revocable

| Aspect | Detail |
|--------|--------|
| **Capability** | Owner signs a grant for a grantee's identity/box key. Mode `full`: entry keys for scope wrapped to grantee's box key; grantee decrypts independently (no journal keys needed). Mode `answers_only`: no keys delivered; grantee asks grounded questions via `ask()`. Scope: sessions, tags, time range, or all. Grants have optional expiry; can be revoked. `share_new()` extends full grants to new entries. |
| **Why policy/prompt fails** | A prompt says "only share X with Y." The model can ignore the prompt, or a compromised process can read everything. Grants are signed records verified on load; keys delivered via X25519 wrapping (only grantee's private key opens); revocation is a signed record that `_authority()` checks. |
| **Where enforced** | `private.py`: `grant()` (validates, signs, wraps keys for full mode), `share_new()` (extends wraps), `revoke()` (marks revoked), `_authority()` (checks active grants, expiry, revocation), `grantee_open()` (grantee unwraps with box key), `ask()` (calls `_authority`, filters by scope). |
| **Test** | `redteam_2_private.py::Grants::test_a_full_grant_delivers_exactly_the_scope_to_the_grantees_own_key`, `test_scopes_by_tag_time_and_everything`, `test_new_entries_reach_a_full_grantee_only_when_the_owner_shares_them`, `test_revocation_and_expiry_stop_access`, `test_an_answers_only_grant_carries_no_keys`, `test_forged_or_altered_policy_records_are_ignored_and_counted`, `test_only_the_unlocked_owner_can_grant`. |
| **Honest limit** | Revoking a full grant cannot unsee what the grantee already decrypted. Answers-only enforcement is by software rules, not mathematics. |

---

### 7. Legacy policy: k-of-n executors, cooling-off, per-beneficiary scope/mode

| Aspect | Detail |
|--------|--------|
| **Capability** | Owner defines executors (2-12, threshold 2+), cooling-off (1-365 days), beneficiaries with per-beneficiary scope and mode (full/answers_only). Legacy key L split via Shamir (k-of-n) with check hash; service key S and beneficiary bundles sealed under L. Versions increment by 1. Death declaration requires k valid executor signatures on identical body for current version. Owner can cancel during cooling-off via `alive` record. Release combines shares, recovers L, opens S, applies policy. |
| **Why policy/prompt fails** | A prompt says "release to beneficiaries after death." The model cannot hold secrets, cannot enforce k-of-n, cannot enforce cooling-off, cannot prevent premature release. The legacy policy is code: Shamir math, signature verification, state machine (living → death_declared_cooling → legacy_effective). |
| **Where enforced** | `private.py`: `set_legacy()` (validates, splits L, seals S and bundles), `prepare_death()` (builds declaration), `declare_death()` (verifies k sigs, version), `alive()` (cancels during cooling-off), `status()` (state machine), `release()` (combines shares, opens S, rebuilds index), `beneficiary_open()` (opens bundle after release), `_authority()` (beneficiary access only after release). |
| **Test** | `redteam_2_private.py::Legacy` — all 16 tests covering policy validation, death declaration, cooling-off, release, beneficiary access, executor non-access, forged records, version skipping, late cancellation. |
| **Honest limit** | Death declaration rests on executors' honesty; choose them and threshold carefully. Real-world death verification is legal/procedural, not in code. |

---

### 8. Grounded answering: whole units, owner-only, relevance, coverage, order, no additions

| Aspect | Detail |
|--------|--------|
| **Capability** | `ground()` returns answers composed of whole sentences (text) or whole transcript segments (media) from the owner's unredacted entries. Each unit must score ≥ `min_score` (default 0.5) on its own. Collective coverage of question terms must reach `coverage_min` (default 0.8) unless a unit scores ≥ 0.9 (strong unit). Units stay in written order (journal position, then offset). Nothing added: no paraphrase, filler, synthetic voice, edited clips. If coverage insufficient, returns `answerable: False` with reason. `verify_answer()` independently re-checks every rule. |
| **Why policy/prompt fails** | A prompt says "only quote my words." The model can paraphrase, hallucinate, stitch phrases, reorder, or answer from its own knowledge. Grounded answering is a deterministic algorithm with hard rules enforced in code: whole units, owner-only filter, relevance threshold, coverage calculation, order preservation, verification function. |
| **Where enforced** | `grounded.py`: `candidates()` (filters to owner, unredacted, splits to whole units), `ground()` (scores, filters by min_score, selects by coverage/strong, sorts by written order), `render()` (quotations + dates only), `verify_answer()` (re-checks: owner speaker, not redacted, whole sentence, exact offsets, written order, relevance ≥ min_score, coverage ≥ coverage_min or strong unit, media clip exact). |
| **Test** | `redteam_2_private.py::GroundedAnswers` — 19 tests covering owner-only, multi-entry pieces, no-answer refusal, model/observer/redacted exclusion, wish exclusion, media clips, verification catching all alterations, weak unit exclusion, written order, coverage addition, bad relevance rejection, ask recorded on chain. |
| **Honest limit** | Word-overlap matcher is weak (misses paraphrase, sarcasm, quoted views). A better matcher can be supplied, but over-scoring lets wrong units in — spot-check required. |

---

### 9. Last-rites wishes: signed, versioned, witnessed, verifiable export

| Aspect | Detail |
|--------|--------|
| **Capability** | Owner signs wishes (property, digital_assets, funeral, care, message, other) with assurance level (0-4). Later wish with same ID supersedes; history stays in chain. Witnesses co-sign with their keys. `statement_of_wishes()` exports packet: notice, owner_sign, exported_at, journal_root, size, head, wishes (payload_text, payload_sha256, record_sha256, position, recorded_at, owner_sig, assurance, tags, witnesses, status, Merkle proof), export_sig. `verify_statement()` checks packet alone. |
| **Why policy/prompt fails** | A prompt says "record my wishes." The model can alter, backdate, forge witnesses, or omit the "not a will" notice. Wishes are signed entries verified on load; witnesses add separate signed records; statement is a signed packet with Merkle proofs; verification is independent code that checks everything from the packet alone. |
| **Where enforced** | `last_rites.py`: `wish()` (validates, signs, writes encrypted entry), `witness()` (verifies witness sig against payload hash), `statement_of_wishes()` (assembles packet, signs), `verify_statement()` (checks export sig, notice, each wish's text hash, owner sig, Merkle inclusion, witness sigs, status, unique IDs). `private.py` `_apply_extra()` verifies wish signatures on load. |
| **Test** | `redteam_2_private.py::LastRites::test_wishes_are_signed_versioned_and_withdrawable`, `test_a_forged_wish_record_does_not_count`, `test_witnesses_count_only_with_valid_signatures`, `test_the_statement_verifies_from_the_packet_alone_and_catches_every_change`, `test_only_the_unlocked_owner_exports_and_revoked_or_replaced_wishes_are_left_out`, `test_a_beneficiary_scoped_to_last_rites_gets_only_the_wishes`. |
| **Honest limit** | Explicitly NOT a will; legal weight depends on jurisdiction; not legal advice. |

---

### 10. Every ask recorded on chain (hash only, no question text)

| Aspect | Detail |
|--------|--------|
| **Capability** | Every `ask()` records a `JOURNAL_ACCESS` event on the Dag: party reference (hash of identity key), role (owner/grantee/beneficiary), answerable (bool), unit count, question SHA-256. Question text never written. If Dag write fails, answer not returned. |
| **Why policy/prompt fails** | A prompt says "log who asked what." The model can omit logs, log selectively, or log false data. The chain write is mandatory and precedes the answer; failure blocks the answer. |
| **Where enforced** | `private.py`: `ask()` calls `_authority()`, builds pool, calls `grounded.ground()`, then `dag.record("JOURNAL_ACCESS", ...)` inside try/except; on `DagError`, raises `JournalRefused` and returns nothing. |
| **Test** | `redteam_2_private.py::GroundedAnswers::test_every_ask_is_recorded_without_the_question_text_and_a_chain_failure_blocks_the_answer`. |
| **Honest limit** | Party reference is a 16-byte hash of the identity key; cannot be reversed to identity without the key. |

---

## DKG + Lattice integration (family predictive loop)

This SDK participates in the family predictive loop as the **record layer (layer 0)**:

```
records (journal entries, ideas, anchors, edges, grants, legacy, wishes, access logs)
    │
    ▼
vega-librarian-sdk (layer 5: memory) — distils lessons from journal records
    │
    ▼
vega-dkg-lattice-sdk (layer 7: knowledge) — builds knowledge graph with origin + licence per fact
    │
    ▼
vega-reasoning-sdk (layer 11: reason) — fidelity, forecasting, routing from the lattice
    │
    ▼
vega-harness-sdk (layer 6: conduct) — pre-registers predicted paths for journal operations
    │
    ▼
vega-metacog-sdk (layer 12: verify) — evidence rungs and completion gate
    │
    ▼
vega-governance-feed-sdk (layer 13: watch) — live view of chains + tamper alarms
    │
    ▼
Human (owner) — decides again, signs new commitments
```

**This SDK's role:** Provides the append-only, tamper-evident, origin-attributed records that seed the entire loop. The journal's thought-genome (ideas with origin, edges, conception receipts) is the highest-fidelity input to the librarian and DKG lattice. The `JOURNAL_ACCESS` events feed the governance feed. The grounded answer verification provides evidence rungs for metacog.

---

## A category of its own: honest differentiation

| Differentiation | What this design does |
|-----------------|----------------------|
| **Governance-first (authority outside the model)** | The model never holds the master key (M), service key (S), or legacy key (L). Every action that reads or releases data requires a human-signed commitment (grant, legacy, wish) verified by code. Authority is single-use and non-transitive. |
| **Deterministic grounded answering** | No model in the loop for answers. `ground()` is a pure function: whole units, owner-only, relevance threshold, coverage, written order, no additions. `verify_answer()` re-checks independently. |
| **Pre-registered predicted paths** | The journal's structure (entries → ideas → edges → receipts) is fixed schema. Grants and legacy policies are signed records with defined state machines. No ad-hoc model decisions. |
| **Single-use human commitments** | Every grant, legacy, wish, death declaration is a signed record. Replay is refused (grant_id tied to canonical body; death declaration tied to legacy version). |
| **Chain-of-custody by default** | Every record hashes the previous; Dag cross-checks; Merkle receipts prove inclusion. Tampering detected on load or by third-party verification. |
| **Lattice-informed foresight** | The journal's origin-attributed ideas, edges, and receipts are the raw material for the DKG lattice → reasoning → harness predicted paths → metacog gates → feed → human decision loop. |

> **Note:** Every differentiation claim is phrased as what THIS design does. The argument "authority held outside the model cannot be replicated by prompt-level policy" follows from the architecture (WHITEPAPER.md section 1).

---

## Standing three cannot-do (included in every capability)

1. **Not production-hardened** — reference implementation with tests; not independently security-reviewed.
2. **Not independently security-reviewed** — crypto is plain Python with `cryptography` library; no expert audit.
3. **Crypto not expert-reviewed** — do not protect real secrets before independent review.
