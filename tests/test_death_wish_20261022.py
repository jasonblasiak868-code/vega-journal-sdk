"""Regression tests (2026-10-22): (1) a death declaration was checked only for the legacy version, so a body with a missing or past cooling_until was accepted and later
crashed status(), or ended the cooling-off at once; (2) a wish containing a credential-shaped value was redacted by the journal, so its JSON no longer parsed and the wish
silently vanished from the statement."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import redteam_2_private as R  # noqa: E402
from vega_journal import last_rites as LR  # noqa: E402
from vega_journal.journal import JournalRefused  # noqa: E402

DAY = 86400


class Death(unittest.TestCase):
    setUp, set, declare = R.Legacy.setUp, R.Legacy.set, R.Legacy.declare

    def sign(self, body, who=("lawyer", "sister")):
        return {n: self.ex[n][0].sign("death", {"death": body}) for n in who}

    def test_a_declaration_with_the_wrong_shape_is_refused(self):
        r = self.r
        self.set()
        good = r.j.prepare_death("ee" * 32)
        bad = [{k: v for k, v in good.items() if k != "cooling_until"}, dict(good, extra=1), dict(good, cooling_until=good["declared_at"]), dict(good, cooling_until=True),
               dict(good, declared_at="1"), dict(good, cooling_until=good["cooling_until"] - 1), dict(good, evidence_sha256="short"), dict(good, evidence_sha256=5)]
        for body in bad:
            with self.assertRaises(JournalRefused, msg=str(body)[:80]):
                r.j.declare_death(body, self.sign(body))
        self.assertEqual(r.j.status(), "living")

    def test_a_back_dated_declaration_cannot_shorten_the_cooling_off(self):
        r = self.r
        self.set()
        old = r.j.prepare_death("ee" * 32, now=int(r.j._clock()) - 60 * DAY)        # signed as if it were declared 60 days ago; the policy cools off for 14 days
        r.j.declare_death(old, self.sign(old))
        self.assertEqual(r.j.status(), "death_declared_cooling")
        r.now["t"] += 13 * DAY
        self.assertEqual(r.j.status(), "death_declared_cooling")
        r.now["t"] += 2 * DAY
        self.assertEqual(r.j.status(), "legacy_effective")


class Wish(unittest.TestCase):
    def test_a_wish_that_would_be_redacted_is_refused_not_lost(self):
        r = R.Rig()
        for secret in ("AKI" + "AABCDEFGHIJKLMNOP", "gh" + "p_" + "a" * 36, "password: hunter2hunter2hunter2"):
            with self.assertRaises(JournalRefused, msg=secret[:10]):
                LR.wish(r.j, r.owner, "keys", "digital_assets", "my cloud key " + secret, "Anna")
            with self.assertRaises(JournalRefused):
                LR.wish(r.j, r.owner, "keys", "digital_assets", "my cloud key", "Anna", "it is " + secret)
        LR.wish(r.j, r.owner, "keys", "digital_assets", "the key is in the safe", "Anna")
        self.assertEqual([p["wish_id"] for _, p in LR.current_wishes(r.j)], ["keys"])


if __name__ == "__main__":
    unittest.main()
