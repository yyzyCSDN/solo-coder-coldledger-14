import unittest
from datetime import datetime, timezone

from coldledger.api import ColdLedgerService
from coldledger.customs.dossier import (
    BLOCKING,
    BATCH_MISMATCH,
    BROKER_RULE_VERSION_CHANGED,
    DeclarationSubmission,
    DOCUMENTS_CHANGED,
    DocumentArtifact,
    DossierContext,
    EXTERNAL_REJECTION,
    LicenseRecord,
    MISSING_DOCUMENT,
    MISSING_LICENSE,
    PREVIOUS_DOSSIER_INCOMPLETE,
    RequirementVersion,
    REQUIREMENT_CONFLICT,
    RULE_VERSION_CHANGED,
    BrokerRuleVersion,
    assemble_dossier,
    replay_declarations,
)

UTC = timezone.utc


def dt(*parts):
    return datetime(*parts, tzinfo=UTC)


class CustomsDossierTests(unittest.TestCase):
    def test_assembles_complete_version_traceable_dossier(self):
        context = DossierContext(
            "D-1", "DE", "BIO", dt(2026, 2, 1),
            origin_country="IN", broker_id="B1", batch_id="LOT-1", license_holder="H1",
        )
        requirement = RequirementVersion(
            "EU-BIO", "v1", "DE", "IN", "BIO", dt(2026, 1, 1),
            required_documents=frozenset({"COO", "BATCH_CERT"}),
            batch_specific_documents=frozenset({"BATCH_CERT"}),
            required_license_types=frozenset({"IMP"}),
            document_rules={"COO": "origin_specific"},
        )
        broker = BrokerRuleVersion(
            "BROKER-CHECK", "v1", "B1", "DE", "IN", "BIO", dt(2026, 1, 1),
            required_documents=frozenset({"BROKER_COVER"}),
        )
        documents = [
            DocumentArtifact("coo-1", "v1", "COO", dt(2026, 1, 2),
                             product_class="BIO", origin_country="IN", destination_country="DE"),
            DocumentArtifact("batch-1", "v1", "BATCH_CERT", dt(2026, 1, 2),
                             batch_id="LOT-1", product_class="BIO",
                             origin_country="IN", destination_country="DE"),
            DocumentArtifact("cover-1", "v1", "BROKER_COVER", dt(2026, 1, 2),
                             product_class="BIO", origin_country="IN",
                             destination_country="DE", broker_id="B1"),
        ]
        license_ = LicenseRecord(
            "imp-1", "v1", "H1", "IMP", "DE", "BIO",
            dt(2026, 1, 1), dt(2026, 1, 1), dt(2027, 1, 1), "IN",
        )

        dossier = assemble_dossier(
            context, [requirement], documents, [broker], [license_],
            assembled_at=dt(2026, 2, 1),
        )

        self.assertTrue(dossier.complete)
        self.assertEqual(
            [(trace.rule_id, trace.version) for trace in dossier.requirement_rules],
            [("EU-BIO", "v1")],
        )
        self.assertEqual(
            [(trace.rule_id, trace.version) for trace in dossier.broker_rules],
            [("BROKER-CHECK", "v1")],
        )
        selected = {selection.document_type: selection.artifact.artifact_id
                    for selection in dossier.document_selections}
        self.assertEqual(selected, {
            "BATCH_CERT": "batch-1",
            "BROKER_COVER": "cover-1",
            "COO": "coo-1",
        })
        self.assertEqual(dossier.license_selections[0].license.license_id, "imp-1")
        self.assertEqual(len(dossier.manifest_digest), 64)
        self.assertEqual(ColdLedgerService().assemble_customs_dossier(
            context, [requirement], documents, [broker], [license_],
            assembled_at=dt(2026, 2, 1),
        ).manifest_digest, dossier.manifest_digest)

    def test_reports_missing_and_context_conflicts_without_hiding_candidates(self):
        context = DossierContext(
            "D-2", "DE", "BIO", dt(2026, 3, 1),
            origin_country="IN", batch_id="LOT-9", license_holder="H1",
        )
        requirement = RequirementVersion(
            "EU-BIO", "v2", "DE", "IN", "BIO", dt(2026, 1, 1),
            required_documents=frozenset({"COO", "BATCH_CERT"}),
            batch_specific_documents=frozenset({"BATCH_CERT"}),
            required_license_types=frozenset({"IMP"}),
        )
        documents = [
            DocumentArtifact(
                "coo-wrong", "v1", "COO", dt(2026, 1, 1),
                origin_country="US", product_class="BIO", destination_country="DE",
            ),
            DocumentArtifact(
                "batch-old", "v1", "BATCH_CERT", dt(2026, 1, 1),
                batch_id="LOT-OLD", product_class="BIO",
                origin_country="IN", destination_country="DE",
            ),
        ]
        license_ = LicenseRecord(
            "imp-future", "v1", "H1", "IMP", "DE", "BIO",
            dt(2026, 4, 1), dt(2026, 4, 1), dt(2027, 1, 1), "IN",
        )

        dossier = assemble_dossier(context, [requirement], documents, [], [license_])
        codes = {issue.code for issue in dossier.issues if issue.severity == BLOCKING}

        self.assertFalse(dossier.complete)
        self.assertIn(MISSING_DOCUMENT, codes)
        self.assertIn(BATCH_MISMATCH, codes)
        self.assertIn(MISSING_LICENSE, codes)
        coo = next(selection for selection in dossier.document_selections
                   if selection.document_type == "COO")
        self.assertEqual(coo.candidate_findings[0].subject_id, "coo-wrong")

    def test_rule_conflict_is_blocking_and_traced(self):
        context = DossierContext("D-3", "DE", "BIO", dt(2026, 2, 1), origin_country="IN")
        requirement = RequirementVersion(
            "CUSTOMS-BASE", "v1", "DE", "IN", "BIO", dt(2026, 1, 1),
            required_documents=frozenset({"COO"}),
        )
        broker = BrokerRuleVersion(
            "B", "v1", "*", "DE", "IN", "BIO", dt(2026, 1, 1),
            forbidden_documents=frozenset({"COO"}),
        )
        coo = DocumentArtifact(
            "coo-conflict", "v1", "COO", dt(2026, 1, 1),
            product_class="BIO", origin_country="IN", destination_country="DE",
        )
        dossier = assemble_dossier(context, [requirement], [coo], [broker], [])
        codes = {issue.code for issue in dossier.issues}
        self.assertIn(REQUIREMENT_CONFLICT, codes)

    def test_more_specific_rule_version_overrides_country_wide_version(self):
        context = DossierContext("D-4", "DE", "BIO", dt(2026, 2, 1), origin_country="IN")
        general = RequirementVersion(
            "EU-BIO", "v1", "DE", "*", "BIO", dt(2026, 1, 1),
            required_documents=frozenset({"GENERAL_DOC"}),
        )
        specific = RequirementVersion(
            "EU-BIO", "v2", "DE", "IN", "BIO", dt(2026, 1, 15),
            required_documents=frozenset({"ORIGIN_DOC"}),
        )
        dossier = assemble_dossier(context, [general, specific], [], [], [])
        self.assertFalse(dossier.complete)
        self.assertEqual(dossier.requirement_rules[0].version, "v2")
        self.assertEqual(dossier.document_selections[0].document_type, "ORIGIN_DOC")

    def test_unknown_artifact_is_blocking_during_replay(self):
        context = DossierContext("D-5", "DE", "BIO", dt(2026, 2, 1))
        rule = RequirementVersion(
            "EU-BIO", "v1", "DE", "*", "BIO", dt(2026, 1, 1),
            required_documents=frozenset({"COO"}),
        )
        submission = DeclarationSubmission("D-5", 1, context, frozenset({"missing"}))
        replayed = replay_declarations([submission], [rule], [], [], [])
        self.assertFalse(replayed[0].dossier.complete)
        self.assertIn("UNKNOWN_DOCUMENT", {issue.code for issue in replayed[0].dossier.issues})
        with self.assertRaises(ValueError):
            assemble_dossier(context, [rule], [], [], [], included_artifact_ids=frozenset({"missing"}))

    def test_replays_old_submissions_with_then_effective_rules_and_explains_resubmission(self):
        v1 = RequirementVersion(
            "EU-BIO", "v1", "DE", "IN", "BIO", dt(2026, 1, 1),
            required_documents=frozenset({"COO"}),
            effective_to=dt(2026, 5, 1),
        )
        v2 = RequirementVersion(
            "EU-BIO", "v2", "DE", "IN", "BIO", dt(2026, 5, 1),
            required_documents=frozenset({"COO", "BATCH_CERT"}),
            batch_specific_documents=frozenset({"BATCH_CERT"}),
        )
        broker_v1 = BrokerRuleVersion(
            "BROKER", "v1", "*", "DE", "IN", "BIO", dt(2026, 1, 1),
            required_documents=frozenset({"COO"}),
            effective_to=dt(2026, 5, 1),
        )
        broker_v2 = BrokerRuleVersion(
            "BROKER", "v2", "*", "DE", "IN", "BIO", dt(2026, 5, 1),
            required_documents=frozenset({"BROKER_COVER"}),
        )
        artifacts = [
            DocumentArtifact("coo-1", "v1", "COO", dt(2026, 1, 1),
                             product_class="BIO", origin_country="IN", destination_country="DE"),
            DocumentArtifact("coo-2", "v2", "COO", dt(2026, 5, 1),
                             product_class="BIO", origin_country="IN", destination_country="DE"),
            DocumentArtifact("batch-2", "v1", "BATCH_CERT", dt(2026, 5, 1),
                             batch_id="LOT-2", product_class="BIO",
                             origin_country="IN", destination_country="DE"),
            DocumentArtifact("cover-2", "v1", "BROKER_COVER", dt(2026, 5, 1),
                             product_class="BIO", origin_country="IN", destination_country="DE"),
        ]

        def submission(revision, at, ids, batch_id="*"):
            return DeclarationSubmission(
                "D-HIST", revision,
                DossierContext("D-HIST", "DE", "BIO", at, "IN", "*", batch_id),
                frozenset(ids),
            )

        rows = [
            submission(1, dt(2026, 2, 1), frozenset()),
            submission(2, dt(2026, 2, 2), frozenset({"coo-1"})),
            submission(3, dt(2026, 6, 1), frozenset({"coo-2", "batch-2", "cover-2"}), "LOT-2"),
        ]

        result = ColdLedgerService().replay_customs_declarations(
            rows, [v1, v2], artifacts, [broker_v1, broker_v2], []
        )

        self.assertFalse(result[0].dossier.complete)
        self.assertTrue(result[1].dossier.complete)
        self.assertTrue(result[2].dossier.complete)
        self.assertEqual(result[0].dossier.requirement_rules[0].version, "v1")
        self.assertEqual(result[1].dossier.requirement_rules[0].version, "v1")
        self.assertEqual(result[2].dossier.requirement_rules[0].version, "v2")
        self.assertIn(PREVIOUS_DOSSIER_INCOMPLETE, result[1].resubmission.codes)
        self.assertIn(DOCUMENTS_CHANGED, result[1].resubmission.codes)
        self.assertIn(RULE_VERSION_CHANGED, result[2].resubmission.codes)
        self.assertIn(BROKER_RULE_VERSION_CHANGED, result[2].resubmission.codes)
        self.assertIn(DOCUMENTS_CHANGED, result[2].resubmission.codes)

    def test_external_rejection_is_explicit_reason_even_when_contents_match(self):
        context = DossierContext("D-EXT", "DE", "BIO", dt(2026, 2, 1), origin_country="IN")
        rule = RequirementVersion(
            "EU-BIO", "v1", "DE", "IN", "BIO", dt(2026, 1, 1),
            required_documents=frozenset({"COO"}),
        )
        coo = DocumentArtifact("coo", "v1", "COO", dt(2026, 1, 1),
                               product_class="BIO", origin_country="IN", destination_country="DE")
        rows = [
            DeclarationSubmission("D-EXT", 1, context, frozenset({"coo"})),
            DeclarationSubmission("D-EXT", 2, context, frozenset({"coo"}),
                                  frozenset({"CUSTOMS_R01"})),
        ]
        result = replay_declarations(rows, [rule], [coo])
        self.assertIn(EXTERNAL_REJECTION, result[1].resubmission.codes)


if __name__ == "__main__":
    unittest.main()
