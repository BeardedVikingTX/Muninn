import unittest
from core.confidence import (Evidence, EvidenceKind as K, EvidenceQuality as Q,
                        ScopeStatus as S, FindingStatus as F, assess_finding)


def evidence(kind, i, group=None, controlled=True, reproducible=True):
    return Evidence(str(i), kind, Q.HIGH, group or str(i),
                    controlled=controlled, reproducible=reproducible)


class ConfidenceTests(unittest.TestCase):
    def test_empty_unknown(self):
        a = assess_finding('x', [])
        self.assertEqual(a.status, F.INCONCLUSIVE)
        self.assertEqual(a.score, 0)

    def test_indicator_not_validated(self):
        a = assess_finding('x', [evidence(K.INDICATOR, 1)], scope=S.AUTHORIZED)
        self.assertEqual(a.status, F.CANDIDATE)

    def test_validation_requires_all_gates(self):
        ev = [evidence(K.IMPACT, 1), evidence(K.REPRODUCTION, 2),
              evidence(K.NEGATIVE_CONTROL, 3), evidence(K.DIFFERENTIAL, 4)]
        a = assess_finding('x', ev, scope=S.AUTHORIZED,
                           security_impact_demonstrated=True, controls_passed=True)
        self.assertEqual(a.status, F.VALIDATED)
        self.assertGreaterEqual(a.score, 90)
        b = assess_finding('x', ev, scope=S.UNKNOWN,
                           security_impact_demonstrated=True, controls_passed=True)
        self.assertNotEqual(b.status, F.VALIDATED)

    def test_contradiction_blocks_validation(self):
        ev = [evidence(K.IMPACT, 1), evidence(K.REPRODUCTION, 2),
              evidence(K.NEGATIVE_CONTROL, 3), evidence(K.DIFFERENTIAL, 4),
              evidence(K.CONTRADICTION, 5)]
        a = assess_finding('x', ev, scope=S.AUTHORIZED,
                           security_impact_demonstrated=True, controls_passed=True)
        self.assertEqual(a.status, F.INCONCLUSIVE)
        self.assertLessEqual(a.score, 45)

    def test_duplicate_fingerprint(self):
        ev = [Evidence('1', K.INDICATOR, fingerprint='same'),
              Evidence('2', K.INDICATOR, fingerprint='same')]
        a = assess_finding('x', ev, scope=S.AUTHORIZED)
        self.assertEqual(a.evidence_count, 1)

    def test_duplicate_id_rejected(self):
        with self.assertRaises(ValueError):
            assess_finding('x', [evidence(K.INDICATOR, 1), evidence(K.IMPACT, 1)])

    def test_unstable_blocks_validation(self):
        ev = [evidence(K.IMPACT, 1), evidence(K.REPRODUCTION, 2),
              evidence(K.NEGATIVE_CONTROL, 3), evidence(K.DIFFERENTIAL, 4)]
        a = assess_finding('x', ev, scope=S.AUTHORIZED,
                           security_impact_demonstrated=True, controls_passed=True,
                           environment_unstable=True)
        self.assertNotEqual(a.status, F.VALIDATED)
        self.assertLessEqual(a.score, 35)

    def test_prohibited_never_validated(self):
        ev = [evidence(K.IMPACT, 1), evidence(K.REPRODUCTION, 2),
              evidence(K.NEGATIVE_CONTROL, 3), evidence(K.DIFFERENTIAL, 4)]
        a = assess_finding('x', ev, scope=S.PROHIBITED,
                           security_impact_demonstrated=True, controls_passed=True)
        self.assertEqual(a.status, F.INCONCLUSIVE)


if __name__ == '__main__':
    unittest.main()

