"""The 3 approved offensive-ext fixes (verify/lockout behaviour left untouched):
atomic review.json write, adcs_esc family alignment, scope strict-mode."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "offensive-ext"))

import emit        # noqa: E402
import narrate     # noqa: E402
import pipeline    # noqa: E402
import attack      # noqa: E402


class AtomicWriteTests(unittest.TestCase):
    def test_preserves_existing_review_and_leaves_no_temp(self):
        d = Path(tempfile.mkdtemp())
        (d / "review.json").write_text(json.dumps({
            "schema": 3, "analyst_summary": "S", "reviewer": "R", "approved_at": "T",
            "cases": [{"id": "AUTH", "state": "bekliyor"}],
            "findings": [{"id": "PX-001", "title": "existing analyst finding"}]}), encoding="utf-8")
        emit.emit_findings(str(d), [{"title": "kerberoast SVC", "asset": "dc", "description": "d",
                                     "impact": "i", "recommendation": "r", "severity": "high",
                                     "type": "kerberoast"}], reviewer="Tester")
        rv = json.loads((d / "review.json").read_text(encoding="utf-8"))
        # Our analyst ledger survived; the offensive finding was appended.
        self.assertEqual(rv["analyst_summary"], "S")
        self.assertEqual(rv["cases"], [{"id": "AUTH", "state": "bekliyor"}])
        titles = {f["title"] for f in rv["findings"]}
        self.assertIn("existing analyst finding", titles)
        self.assertIn("kerberoast SVC", titles)
        # No temp artefact left behind by the atomic write.
        self.assertFalse((d / "review.json.offensive.tmp").exists())


class AdcsFamilyTests(unittest.TestCase):
    def test_fam_normalizes_variants(self):
        self.assertEqual(narrate._fam("adcs_esc_direct"), "adcs_esc")
        self.assertEqual(narrate._fam("adcs_esc_acl"), "adcs_esc")
        self.assertEqual(narrate._fam("adcs_esc_chain"), "adcs_esc")
        self.assertEqual(narrate._fam("kerberoast"), "kerberoast")

    def test_variant_gets_adcs_narrative_and_killchain_note(self):
        text = narrate.narrate([{"type": "adcs_esc_direct", "asset": "UserAuth",
                                 "severity": "critical", "cvss_score": 9.9}], reached_da=False)
        self.assertIn("AD Sertifika", text)      # the adcs_esc description template fired
        self.assertIn("ADCS/coercion", text)     # kill-chain note recognises the family

    def test_stage_order_covers_variants(self):
        for t in ("adcs_esc", "adcs_esc_direct", "adcs_esc_chain", "adcs_esc_acl"):
            self.assertEqual(pipeline.STAGE_ORDER.get(t), 4, t)


class ScopeStrictTests(unittest.TestCase):
    def _scope(self, text):
        p = Path(tempfile.mkdtemp()) / "scope.txt"
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_valid_scope_parses(self):
        nets, hosts = attack.load_scope(self._scope("10.0.0.0/24\n10.0.0.5\ndc.corp.local\n# note\n"))
        self.assertTrue(any(str(n) == "10.0.0.0/24" for n in nets))
        self.assertIn("dc.corp.local", hosts)

    def test_host_bit_cidr_is_rejected_not_widened(self):
        # 10.0.0.5/24 would silently widen to 10.0.0.0/24 (255 extra hosts) under strict=False.
        with self.assertRaises(ValueError):
            attack.load_scope(self._scope("10.0.0.5/24\n"))

    def test_garbage_line_is_rejected(self):
        with self.assertRaises(ValueError):
            attack.load_scope(self._scope("this is not a host!!\n"))


if __name__ == "__main__":
    unittest.main()
