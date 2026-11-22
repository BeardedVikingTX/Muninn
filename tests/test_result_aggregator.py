import unittest
from dataclasses import replace

from core.confidence import Assessment, FindingStatus
from core.reporting import ReportFinding, ScanReport, Severity, Eligibility, render_json
from core.result_aggregator import ResultAggregator, AggregationError
from core.evidence import EvidenceRecord, ArtifactKind


def finding(fid='f1', *, title='Sanitized finding', evidence=(), status=FindingStatus.CANDIDATE):
    a = Assessment(fid, 8, status, len(evidence), 1, ('indicator',), ('review required',))
    return ReportFinding(fid, title, 'xss', Severity.LOW, a, 'Potential reflection', evidence=tuple(evidence))


def record(eid='e1', fid='f1', digest='a'*64):
    return EvidenceRecord(eid, fid, ArtifactKind.OBSERVATION, 'src1',
                          '2026-01-01T00:00:00+00:00', digest, 4, 'b'*64,
                          eid+'.txt', False)


def scan(sid, *items, program='program', scoped=True, analyzed=2, skipped=1):
    return ScanReport(sid, program, tuple(items), analyzed_transactions=analyzed,
                      skipped_transactions=skipped, scope_policy_verified=scoped)


class AggregationTests(unittest.TestCase):
    def setUp(self):
        self.agg = ResultAggregator()

    def run_aggregate(self, *reports):
        return self.agg.aggregate(iter(reports), scan_id='combined')

    def test_single(self):
        r = self.run_aggregate(scan('s1', finding()))
        self.assertEqual(r.stats.unique_findings, 1)
        self.assertTrue(r.report.scope_policy_verified)

    def test_deduplicates_matching_id(self):
        f = finding()
        r = self.run_aggregate(scan('s1', f), scan('s2', f))
        self.assertEqual(r.stats.input_findings, 2)
        self.assertEqual(r.stats.duplicate_observations, 1)
        self.assertEqual(len(r.report.findings), 1)

    def test_distinct_ids_not_merged(self):
        r = self.run_aggregate(scan('s1', finding('f1')), scan('s2', finding('f2')))
        self.assertEqual(r.stats.unique_findings, 2)

    def test_evidence_union(self):
        f1 = finding(evidence=(record('e1'),))
        f2 = finding(evidence=(record('e2'),))
        # Assessment must be unchanged, including evidence_count; models do not rescore.
        f2 = replace(f2, assessment=f1.assessment)
        r = self.run_aggregate(scan('s1', f1), scan('s2', f2))
        self.assertEqual([e.evidence_id for e in r.report.findings[0].evidence], ['e1', 'e2'])
        self.assertEqual(r.stats.unique_evidence, 2)

    def test_evidence_same_id_dedup(self):
        f = finding(evidence=(record(),))
        r = self.run_aggregate(scan('s1', f), scan('s2', f))
        self.assertEqual(r.stats.unique_evidence, 1)

    def test_conflicting_title_rejected(self):
        with self.assertRaisesRegex(AggregationError, 'conflicting claims'):
            self.run_aggregate(scan('s1', finding()), scan('s2', finding(title='Different')))

    def test_conflicting_severity_rejected(self):
        with self.assertRaises(AggregationError):
            self.run_aggregate(scan('s1', finding()), scan('s2', replace(finding(), severity=Severity.HIGH)))

    def test_conflicting_status_rejected(self):
        with self.assertRaises(AggregationError):
            self.run_aggregate(scan('s1', finding()), scan('s2', finding(status=FindingStatus.REFUTED)))

    def test_conflicting_evidence_rejected(self):
        f1 = finding(evidence=(record(),))
        f2 = finding(evidence=(record(digest='c'*64),))
        with self.assertRaisesRegex(AggregationError, 'conflicting evidence'):
            self.run_aggregate(scan('s1', f1), scan('s2', f2))

    def test_cross_program_rejected(self):
        with self.assertRaisesRegex(AggregationError, 'cross-program'):
            self.run_aggregate(scan('s1'), scan('s2', program='other'))

    def test_requested_program_mismatch(self):
        with self.assertRaises(AggregationError):
            self.agg.aggregate([scan('s1')], scan_id='combined', program_id='other')

    def test_duplicate_source_scan_rejected(self):
        with self.assertRaises(AggregationError):
            self.run_aggregate(scan('s1'), scan('s1'))

    def test_output_source_collision_rejected(self):
        with self.assertRaises(AggregationError):
            self.agg.aggregate([scan('s1')], scan_id='s1')

