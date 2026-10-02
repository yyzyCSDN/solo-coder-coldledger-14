import unittest
from datetime import date

from coldledger.customs.dossier import (
    FindingKind, assemble, check_stale, resubmission_check,
)
from coldledger.customs.dossier_replay import file_declaration, replay
from coldledger.customs.dossier_rules import Constraint, Facts, RuleKind, RuleStore, RuleVersion
from coldledger.customs.dossier_validate import Document, validate

D = date
REQ, WAIVE = RuleKind.REQUIRE, RuleKind.WAIVE


def build_store():
    s = RuleStore()
    s.publish(RuleVersion("DE-INVOICE", 1, REQ, "COMMERCIAL_INVOICE",
                          destination_country="DE",
                          valid_from=D(2026, 1, 1), recorded_from=D(2026, 1, 1),
                          source_ref="DE-Customs-Gen-2026"))
    s.publish(RuleVersion("DE-COO", 1, REQ, "COO",
                          destination_country="DE",
                          valid_from=D(2026, 1, 1), recorded_from=D(2026, 1, 1),
                          source_ref="DE-Customs-Gen-2026"))
    s.publish(RuleVersion("DE-HEALTH", 1, REQ, "HEALTH_CERT",
                          destination_country="DE", product_class="FOOD",
                          constraints=(Constraint("max_age_days", 30), Constraint("original_only", True)),
                          valid_from=D(2026, 1, 1), valid_to=D(2026, 3, 31),
                          recorded_from=D(2026, 1, 1), source_ref="DE-LFGB-2025-118"))
    s.publish(RuleVersion("DE-HEALTH-WAIVER", 1, WAIVE, "HEALTH_CERT",
                          destination_country="DE", product_class="FOOD",
                          license_type="DE_FOOD_IMPORT",
                          valid_from=D(2026, 1, 1), recorded_from=D(2026, 1, 1),
                          source_ref="DE-LFGB-2025-118"))
    # recorded 2026-03-15, effective 2026-04-01: tighter cert age + new lab report
    s.publish(RuleVersion("DE-HEALTH", 2, REQ, "HEALTH_CERT",
                          destination_country="DE", product_class="FOOD",
                          constraints=(Constraint("max_age_days", 14), Constraint("original_only", True)),
                          valid_from=D(2026, 4, 1), recorded_from=D(2026, 3, 15),
                          source_ref="DE-LFGB-2026-041"))
    s.publish(RuleVersion("DE-LAB", 1, REQ, "LAB_TEST_REPORT",
                          destination_country="DE", product_class="FOOD",
                          valid_from=D(2026, 4, 1), recorded_from=D(2026, 3, 15),
                          source_ref="DE-LFGB-2026-041"))
    return s


def facts_mar():
    return Facts("DE", "FOOD", "CN", "BROKER-7", None, D(2026, 3, 10), D(2026, 3, 1))


def facts_apr():
    return Facts("DE", "FOOD", "CN", "BROKER-7", None, D(2026, 4, 10), D(2026, 4, 5))


def clean_docs():
    return [
        Document("COMMERCIAL_INVOICE", D(2026, 2, 20), fields={"origin_country": "CN"}),
        Document("COO", D(2026, 2, 21), fields={"origin_country": "CN"}),
        Document("HEALTH_CERT", D(2026, 2, 20)),
    ]


def item(dossier, doc_type):
    return next(i for i in dossier.items if i.doc_type == doc_type)


class AssembleTests(unittest.TestCase):
    def test_assemble_traces_requirements(self):
        d = assemble(build_store(), facts_mar(), D(2026, 3, 1), D(2026, 2, 20))
        self.assertEqual({i.doc_type for i in d.required_items},
                         {"COMMERCIAL_INVOICE", "COO", "HEALTH_CERT"})
        health = item(d, "HEALTH_CERT")
        self.assertEqual(health.required_by, ("DE-HEALTH@v1",))
        self.assertEqual(health.constraints,
                         (Constraint("max_age_days", 30), Constraint("original_only", True)))
        for i in d.required_items:
            self.assertTrue(i.required_by)  # every item carries its source version

    def test_license_waiver(self):
        f = Facts("DE", "FOOD", "CN", "BROKER-7", "DE_FOOD_IMPORT", D(2026, 3, 10), D(2026, 3, 1))
        d = assemble(build_store(), f, D(2026, 3, 1), D(2026, 2, 20))
        self.assertEqual({i.doc_type for i in d.required_items}, {"COMMERCIAL_INVOICE", "COO"})
        health = item(d, "HEALTH_CERT")
        self.assertFalse(health.required)
        self.assertEqual(health.waived_by, ("DE-HEALTH-WAIVER@v1",))

    def test_equal_priority_conflict_keeps_requirement(self):
        s = build_store()
        s.publish(RuleVersion("DE-HEALTH-W2", 1, WAIVE, "HEALTH_CERT",
                              destination_country="DE", product_class="FOOD",
                              valid_from=D(2026, 1, 1), recorded_from=D(2026, 1, 1),
                              source_ref="DE-LFGB-2026-009"))
        d = assemble(s, facts_mar(), D(2026, 3, 1), D(2026, 2, 20))
        self.assertEqual([f.kind for f in d.conflicts], [FindingKind.RULE_CONFLICT])
        self.assertIn("HEALTH_CERT", {i.doc_type for i in d.required_items})  # conservative

    def test_merge_constraints_from_parallel_rules(self):
        s = RuleStore()
        s.publish(RuleVersion("R-A", 1, REQ, "CERT_X", destination_country="DE",
                              constraints=(Constraint("max_age_days", 30),),
                              valid_from=D(2026, 1, 1), recorded_from=D(2026, 1, 1)))
        s.publish(RuleVersion("R-B", 1, REQ, "CERT_X", destination_country="DE",
                              constraints=(Constraint("original_only", True),),
                              valid_from=D(2026, 1, 1), recorded_from=D(2026, 1, 1)))
        f = Facts("DE", "GENERAL", "CN", "B1", None, D(2026, 3, 10), D(2026, 3, 1))
        cert = item(assemble(s, f, D(2026, 3, 1), D(2026, 2, 20)), "CERT_X")
        self.assertEqual(cert.constraints,
                         (Constraint("max_age_days", 30), Constraint("original_only", True)))
        self.assertEqual(cert.required_by, ("R-A@v1", "R-B@v1"))

    def test_store_rejects_rewrite(self):
        s = build_store()
        with self.assertRaises(ValueError):
            s.publish(RuleVersion("DE-COO", 1, REQ, "COO", destination_country="DE"))


class ValidateTests(unittest.TestCase):
    def test_missing_and_mismatch(self):
        d = assemble(build_store(), facts_mar(), D(2026, 3, 1), D(2026, 2, 20))
        docs = [
            Document("COMMERCIAL_INVOICE", D(2026, 2, 20), fields={"origin_country": "CN"}),
            Document("COO", D(2026, 2, 21), fields={"origin_country": "VN"}),
        ]
        findings = validate(d, docs)
        kinds = {f.kind for f in findings}
        self.assertIn(FindingKind.MISSING, kinds)
        self.assertIn(FindingKind.DOC_MISMATCH, kinds)
        missing = next(f for f in findings if f.kind is FindingKind.MISSING)
        self.assertEqual(missing.doc_types, ("HEALTH_CERT",))
        self.assertEqual(missing.rule_refs, ("DE-HEALTH@v1",))

    def test_expired_and_copy(self):
        d = assemble(build_store(), facts_mar(), D(2026, 3, 1), D(2026, 2, 20))
        docs = clean_docs()[:2] + [Document("HEALTH_CERT", D(2026, 1, 5), is_original=False)]
        kinds = {f.kind for f in validate(d, docs)}
        self.assertIn(FindingKind.EXPIRED, kinds)  # issued 64 days before shipment
        self.assertIn(FindingKind.CONSTRAINT_VIOLATION, kinds)  # copy, not original

    def test_clean_dossier_has_no_findings(self):
        d = assemble(build_store(), facts_mar(), D(2026, 3, 1), D(2026, 2, 20))
        self.assertEqual(validate(d, clean_docs()), [])


class TemporalTests(unittest.TestCase):
    def test_resubmission_explains_new_versions(self):
        s = build_store()
        # assembled 2026-03-10 for an April declaration: April rules not yet recorded
        d = assemble(s, facts_apr(), D(2026, 4, 5), D(2026, 3, 10))
        self.assertEqual({i.doc_type for i in d.required_items}, {"COMMERCIAL_INVOICE", "COO"})
        findings = resubmission_check(d, s, D(2026, 3, 20))
        self.assertEqual({f.kind for f in findings}, {FindingKind.RESUBMIT})
        self.assertEqual({dt for f in findings for dt in f.doc_types},
                         {"HEALTH_CERT", "LAB_TEST_REPORT"})
        for f in findings:
            self.assertIn("DE-LFGB-2026-041", f.message)  # source citation in the reason

    def test_no_resubmission_when_change_not_effective(self):
        s = build_store()
        d = assemble(s, facts_mar(), D(2026, 3, 1), D(2026, 2, 20))
        self.assertEqual(resubmission_check(d, s, D(2026, 3, 20)), [])

    def test_stale_checklist_detected(self):
        s = build_store()
        # an April declaration assembled from the March checklist (old versions)
        d = assemble(s, facts_apr(), D(2026, 3, 1), D(2026, 2, 20))
        findings = check_stale(d, s)
        self.assertTrue(findings)
        self.assertEqual({f.kind for f in findings}, {FindingKind.STALE_RULESET})
        self.assertTrue(any("HEALTH_CERT" in f.message for f in findings))

    def test_replay_as_known_then_reproduces_filed_result(self):
        s = build_store()
        decl = file_declaration("D-1", s, facts_mar(), clean_docs(), as_of_recorded=D(2026, 2, 20))
        self.assertEqual(decl.findings, ())
        # backdated correction recorded months later
        s.publish(RuleVersion("DE-COO", 2, REQ, "COO",
                              destination_country="DE",
                              constraints=(Constraint("original_only", True),),
                              valid_from=D(2026, 2, 1), recorded_from=D(2026, 6, 1),
                              source_ref="DE-Customs-Corr-2026-06"))
        dossier_then, findings_then = replay(s, decl, decl.dossier.as_of_recorded)
        self.assertEqual(dossier_then, decl.dossier)  # rules as known then: identical
        self.assertEqual(findings_then, list(decl.findings))
        dossier_now, _ = replay(s, decl, D(2026, 10, 2))
        self.assertNotEqual(dossier_now, decl.dossier)  # current knowledge sees the correction
        coo = item(dossier_now, "COO")
        self.assertEqual(coo.required_by, ("DE-COO@v2",))
        self.assertEqual(coo.constraints, (Constraint("original_only", True),))


if __name__ == "__main__":
    unittest.main()
