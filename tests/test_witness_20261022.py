"""Regression tests (2026-10-22): verify_statement counted a witness listed twice as two witnesses, so a packet with ONE witness repeated verified as 'witnessed' (the owner
re-signs the packet). The owner was also allowed to witness their own wish. Witnesses now count once each, and never the owner."""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import redteam_2_private as R  # noqa: E402
from vega_journal import crypto, last_rites as LR  # noqa: E402
from vega_journal.journal import JournalRefused  # noqa: E402


def resign(r, pkt):
    body = {k: v for k, v in pkt.items() if k != "export_sig"}
    pkt["export_sig"] = r.owner.sign("statement", body)
    return pkt


class Witnesses(unittest.TestCase):
    def setUp(self):
        self.r = R.Rig()
        self.w = LR.wish(self.r.j, self.r.owner, "house", "property", "The house", "Anna and Ben")

    def test_one_witness_repeated_is_not_two_witnesses(self):
        r = self.r
        LR.witness(r.j, self.w["sha256"], crypto.Signer())
        pkt = LR.statement_of_wishes(r.j, r.owner)
        self.assertEqual(LR.verify_statement(pkt), [])
        forged = copy.deepcopy(pkt)
        one = forged["wishes"][0]["witnesses"][0]
        forged["wishes"][0]["witnesses"] = [one, dict(one)]
        forged["wishes"][0]["status"] = "witnessed"
        self.assertTrue(LR.verify_statement(resign(r, forged)), "a repeated witness must be reported")

    def test_the_owner_cannot_witness_their_own_wish(self):
        r = self.r
        with self.assertRaises(JournalRefused):
            LR.witness(r.j, self.w["sha256"], r.owner)
        LR.witness(r.j, self.w["sha256"], crypto.Signer())
        pkt = copy.deepcopy(LR.statement_of_wishes(r.j, r.owner))
        body = {"wish": pkt["wishes"][0]["record_sha256"], "payload_sha256": pkt["wishes"][0]["payload_sha256"]}
        pkt["wishes"][0]["witnesses"].append({"witness_sign": r.owner.public.hex(), "sig": r.owner.sign("witness", body)})
        pkt["wishes"][0]["status"] = "witnessed"
        self.assertTrue(LR.verify_statement(resign(r, pkt)), "the owner listed as a witness must be reported")

    def test_two_different_witnesses_still_make_a_witnessed_wish(self):
        r = self.r
        LR.witness(r.j, self.w["sha256"], crypto.Signer())
        LR.witness(r.j, self.w["sha256"], crypto.Signer())
        pkt = LR.statement_of_wishes(r.j, r.owner)
        self.assertEqual((pkt["wishes"][0]["status"], LR.verify_statement(pkt)), ("witnessed", []))


if __name__ == "__main__":
    unittest.main()
