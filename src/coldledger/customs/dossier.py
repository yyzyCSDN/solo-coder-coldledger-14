"""Version-aware customs dossier assembly and historical replay.

The functions in this module never mutate catalogs.  Every decision is based on
rules, documents and licenses that were effective at the declaration's event
time, so an old declaration can be replayed without accidentally using a
requirement that was introduced later.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import json
from typing import Iterable

from ..core.clock import utc

BLOCKING = "blocking"
WARNING = "warning"

# Issue codes
MISSING_DOCUMENT = "MISSING_DOCUMENT"
FUTURE_DOCUMENT = "FUTURE_DOCUMENT"
NOT_YET_VALID_DOCUMENT = "NOT_YET_VALID_DOCUMENT"
EXPIRED_DOCUMENT = "EXPIRED_DOCUMENT"
SUPERSEDED_DOCUMENT = "SUPERSEDED_DOCUMENT"
REVOKED_DOCUMENT = "REVOKED_DOCUMENT"
DOCUMENT_CONTEXT_MISMATCH = "DOCUMENT_CONTEXT_MISMATCH"
BATCH_MISMATCH = "BATCH_MISMATCH"
BATCH_NOT_IDENTIFIED = "BATCH_NOT_IDENTIFIED"
CONFLICTING_DOCUMENTS = "CONFLICTING_DOCUMENTS"
MULTIPLE_APPLICABLE_DOCUMENTS = "MULTIPLE_APPLICABLE_DOCUMENTS"
OBSOLETE_DOCUMENT = "OBSOLETE_DOCUMENT"
UNKNOWN_DOCUMENT = "UNKNOWN_DOCUMENT"
RULE_VERSION_CONFLICT = "RULE_VERSION_CONFLICT"
REQUIREMENT_CONFLICT = "REQUIREMENT_CONFLICT"
MISSING_LICENSE = "MISSING_LICENSE"
LICENSE_HOLDER_MISSING = "LICENSE_HOLDER_MISSING"
FUTURE_LICENSE = "FUTURE_LICENSE"
LICENSE_NOT_YET_VALID = "LICENSE_NOT_YET_VALID"
EXPIRED_LICENSE = "EXPIRED_LICENSE"
SUSPENDED_LICENSE = "SUSPENDED_LICENSE"
SUPERSEDED_LICENSE = "SUPERSEDED_LICENSE"
REVOKED_LICENSE = "REVOKED_LICENSE"
LICENSE_SCOPE_MISMATCH = "LICENSE_SCOPE_MISMATCH"
CONFLICTING_LICENSES = "CONFLICTING_LICENSES"
MULTIPLE_APPLICABLE_LICENSES = "MULTIPLE_APPLICABLE_LICENSES"
OBSOLETE_LICENSE = "OBSOLETE_LICENSE"

# Resubmission reason codes
EXTERNAL_REJECTION = "EXTERNAL_REJECTION"
PREVIOUS_DOSSIER_INCOMPLETE = "PREVIOUS_DOSSIER_INCOMPLETE"
CONTEXT_CHANGED = "CONTEXT_CHANGED"
RULE_VERSION_CHANGED = "RULE_VERSION_CHANGED"
BROKER_RULE_VERSION_CHANGED = "BROKER_RULE_VERSION_CHANGED"
DOCUMENTS_CHANGED = "DOCUMENTS_CHANGED"
LICENSE_CHANGED = "LICENSE_CHANGED"
UNCHANGED_RESUBMISSION = "UNCHANGED_RESUBMISSION"

WILDCARD = "*"
CUSTOMS_KIND = "customs"
BROKER_KIND = "broker"
DOCUMENT_POLICIES = frozenset({
    "batch_specific",
    "product_specific",
    "origin_specific",
    "destination_specific",
    "broker_specific",
})


@dataclass(frozen=True)
class DossierContext:
    declaration_id: str
    destination_country: str
    product_class: str
    event_time: datetime
    origin_country: str = WILDCARD
    broker_id: str = WILDCARD
    batch_id: str = WILDCARD
    license_holder: str | None = None

    def __post_init__(self) -> None:
        _aware(self.event_time, "event_time")
        for name in ("destination_country", "product_class", "origin_country", "broker_id", "batch_id"):
            if not getattr(self, name):
                raise ValueError(f"{name} is required")

    def canonical(self) -> dict[str, object]:
        return {
            "declaration_id": self.declaration_id,
            "destination_country": self.destination_country,
            "origin_country": self.origin_country,
            "product_class": self.product_class,
            "broker_id": self.broker_id,
            "batch_id": self.batch_id,
            "license_holder": self.license_holder,
            "event_time": _iso(self.event_time),
        }


@dataclass(frozen=True)
class RequirementVersion:
    """One immutable customs requirement version."""

    requirement_id: str
    version: str
    destination_country: str
    origin_country: str
    product_class: str
    effective_from: datetime
    required_documents: frozenset[str] = field(default_factory=frozenset)
    batch_specific_documents: frozenset[str] = field(default_factory=frozenset)
    required_license_types: frozenset[str] = field(default_factory=frozenset)
    document_rules: dict[str, str] = field(default_factory=dict)
    effective_to: datetime | None = None
    priority: int = 0

    def __post_init__(self) -> None:
        _validate_window(self.effective_from, self.effective_to)
        if not self.required_documents and not self.required_license_types:
            raise ValueError("requirement must demand a document or license")
        if not self.batch_specific_documents <= self.required_documents:
            raise ValueError("batch-specific documents must also be required")
        if not set(self.document_rules) <= self.required_documents:
            raise ValueError("document rules must refer to required documents")
        if not set(self.document_rules.values()) <= DOCUMENT_POLICIES:
            raise ValueError("unknown document rule")


@dataclass(frozen=True)
class BrokerRuleVersion:
    """One immutable version of a broker's clearance checklist."""

    rule_id: str
    version: str
    broker_id: str
    destination_country: str
    origin_country: str
    product_class: str
    effective_from: datetime
    required_documents: frozenset[str] = field(default_factory=frozenset)
    forbidden_documents: frozenset[str] = field(default_factory=frozenset)
    batch_specific_documents: frozenset[str] = field(default_factory=frozenset)
    required_license_types: frozenset[str] = field(default_factory=frozenset)
    document_rules: dict[str, str] = field(default_factory=dict)
    effective_to: datetime | None = None
    priority: int = 0

    def __post_init__(self) -> None:
        _validate_window(self.effective_from, self.effective_to)
        if not (self.required_documents or self.forbidden_documents or self.required_license_types):
            raise ValueError("broker rule must require, forbid, or demand a license")
        if self.required_documents & self.forbidden_documents:
            raise ValueError("document cannot be both required and forbidden by one rule")
        if not self.batch_specific_documents <= self.required_documents:
            raise ValueError("batch-specific documents must also be required")
        if not set(self.document_rules) <= self.required_documents:
            raise ValueError("document rules must refer to required documents")
        if not set(self.document_rules.values()) <= DOCUMENT_POLICIES:
            raise ValueError("unknown document rule")


@dataclass(frozen=True)
class DocumentArtifact:
    artifact_id: str
    version: str
    document_type: str
    issued_at: datetime
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    batch_id: str = WILDCARD
    product_class: str = WILDCARD
    origin_country: str = WILDCARD
    destination_country: str = WILDCARD
    broker_id: str = WILDCARD
    superseded_at: datetime | None = None
    revoked_at: datetime | None = None
    sha256: str = ""

    def __post_init__(self) -> None:
        _aware(self.issued_at, "issued_at")
        start = self.valid_from or self.issued_at
        _aware(start, "valid_from")
        if self.valid_to is not None:
            _aware(self.valid_to, "valid_to")
            if utc(self.valid_to) <= utc(start):
                raise ValueError("document valid_to must be after valid_from")
        for value in (self.superseded_at, self.revoked_at):
            if value is not None and utc(value) < utc(self.issued_at):
                raise ValueError("document lifecycle date is before issued_at")

    def identity(self) -> tuple[str, str, str]:
        return (self.artifact_id, self.version, self.sha256)


@dataclass(frozen=True)
class LicenseRecord:
    license_id: str
    version: str
    holder: str
    license_type: str
    jurisdiction: str
    product_class: str
    issued_at: datetime
    valid_from: datetime
    valid_to: datetime | None
    origin_country: str = WILDCARD
    suspended_at: datetime | None = None
    superseded_at: datetime | None = None
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        _aware(self.issued_at, "issued_at")
        _validate_window(self.valid_from, self.valid_to)
        for name in ("suspended_at", "superseded_at", "revoked_at"):
            value = getattr(self, name)
            if value is not None and utc(value) < utc(self.issued_at):
                raise ValueError(f"license {name} is before issued_at")

    def identity(self) -> tuple[str, str]:
        return (self.license_id, self.version)


@dataclass(frozen=True)
class RuleTrace:
    kind: str
    rule_id: str
    version: str
    destination_country: str
    origin_country: str
    product_class: str
    broker_id: str
    required_documents: tuple[str, ...]
    forbidden_documents: tuple[str, ...]
    batch_specific_documents: tuple[str, ...]
    required_license_types: tuple[str, ...]
    document_rules: tuple[tuple[str, str], ...]
    effective_from: datetime
    effective_to: datetime | None
    priority: int = 0

    def key(self) -> tuple[str, str]:
        return (self.kind, self.rule_id)

    def canonical(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "rule_id": self.rule_id,
            "version": self.version,
            "scope": [
                self.destination_country,
                self.origin_country,
                self.product_class,
                self.broker_id,
            ],
            "required_documents": list(self.required_documents),
            "forbidden_documents": list(self.forbidden_documents),
            "batch_specific_documents": list(self.batch_specific_documents),
            "required_license_types": list(self.required_license_types),
            "document_rules": list(map(list, self.document_rules)),
            "effective_from": _iso(self.effective_from),
            "effective_to": _iso(self.effective_to) if self.effective_to else None,
            "priority": self.priority,
        }


@dataclass(frozen=True)
class CandidateFinding:
    subject_id: str
    version: str
    code: str
    message: str


@dataclass(frozen=True)
class DocumentSelection:
    document_type: str
    status: str
    artifact: DocumentArtifact | None
    sources: tuple[RuleTrace, ...]
    candidate_findings: tuple[CandidateFinding, ...] = ()
    conflicting_artifacts: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class LicenseSelection:
    license_type: str
    status: str
    license: LicenseRecord | None
    sources: tuple[RuleTrace, ...]
    candidate_findings: tuple[CandidateFinding, ...] = ()
    conflicting_licenses: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class DossierIssue:
    code: str
    severity: str
    message: str
    document_type: str = ""
    license_type: str = ""
    rule_id: str = ""
    subject_type: str = ""
    subject_id: str = ""
    artifact_id: str = ""
    versions: tuple[str, ...] = ()

    def key(self) -> tuple[object, ...]:
        return (
            self.code, self.severity, self.message, self.document_type,
            self.license_type, self.rule_id, self.subject_type,
            self.subject_id, self.artifact_id, self.versions,
        )


@dataclass(frozen=True)
class Dossier:
    context: DossierContext
    assembled_at: datetime
    requirement_rules: tuple[RuleTrace, ...]
    broker_rules: tuple[RuleTrace, ...]
    document_selections: tuple[DocumentSelection, ...]
    license_selections: tuple[LicenseSelection, ...]
    submitted_artifact_ids: tuple[str, ...]
    unused_artifacts: tuple[DocumentArtifact, ...]
    issues: tuple[DossierIssue, ...]
    complete: bool
    manifest_digest: str


@dataclass(frozen=True)
class DeclarationSubmission:
    declaration_id: str
    revision: int
    context: DossierContext
    artifact_ids: frozenset[str] = field(default_factory=frozenset)
    external_rejection_codes: frozenset[str] = field(default_factory=frozenset)
    note: str = ""

    def __post_init__(self) -> None:
        if self.revision < 1:
            raise ValueError("revision must start at 1")
        if self.context.declaration_id != self.declaration_id:
            raise ValueError("submission and context declaration ids differ")


@dataclass(frozen=True)
class ResubmissionReason:
    revision: int
    codes: tuple[str, ...]
    explanations: tuple[str, ...]
    changed_context: tuple[tuple[str, str, str], ...] = ()
    added_artifacts: tuple[str, ...] = ()
    removed_artifacts: tuple[str, ...] = ()
    replaced_documents: tuple[tuple[str, str | None, str | None], ...] = ()
    changed_rules: tuple[tuple[str, str, str, str], ...] = ()
    changed_licenses: tuple[tuple[str, str | None, str | None], ...] = ()


@dataclass(frozen=True)
class ReplayedDeclaration:
    submission: DeclarationSubmission
    dossier: Dossier
    resubmission: ResubmissionReason | None


def assemble_dossier(
    context: DossierContext,
    requirements: Iterable[RequirementVersion] = (),
    artifacts: Iterable[DocumentArtifact] = (),
    broker_rules: Iterable[BrokerRuleVersion] = (),
    licenses: Iterable[LicenseRecord] = (),
    assembled_at: datetime | None = None,
    included_artifact_ids: Iterable[str] | None = None,
    allow_unknown_artifact_ids: bool = False,
) -> Dossier:
    """Assemble a dossier using only records effective at ``context.event_time``."""

    at = utc(context.event_time)
    assembled = utc(assembled_at) if assembled_at is not None else datetime.now(timezone.utc)
    requirements = tuple(requirements)
    broker_rules = tuple(broker_rules)
    artifacts = tuple(artifacts)
    licenses = tuple(licenses)
    if included_artifact_ids is None:
        included_ids = frozenset(artifact.artifact_id for artifact in artifacts)
    else:
        included_ids = frozenset(included_artifact_ids)
        unknown_ids = included_ids - {artifact.artifact_id for artifact in artifacts}
        if unknown_ids and not allow_unknown_artifact_ids:
            raise ValueError(f"unknown submitted artifact ids: {sorted(unknown_ids)}")
    artifacts = tuple(artifact for artifact in artifacts if artifact.artifact_id in included_ids)

    issues: list[DossierIssue] = []
    customs_traces = _resolve_rule_overlaps(context, _select_customs(context, requirements, at), issues)
    broker_traces = _resolve_rule_overlaps(context, _select_broker(context, broker_rules, at), issues)

    sources: dict[str, list[RuleTrace]] = {}
    batch_specific: set[str] = set()
    license_sources: dict[str, list[RuleTrace]] = {}
    forbidden: dict[str, list[RuleTrace]] = {}
    document_policies: dict[str, set[str]] = {}

    for trace in (*customs_traces, *broker_traces):
        for doc in trace.required_documents:
            sources.setdefault(doc, []).append(trace)
        batch_specific.update(trace.batch_specific_documents)
        for license_type in trace.required_license_types:
            license_sources.setdefault(license_type, []).append(trace)
        for doc, policy in trace.document_rules:
            document_policies.setdefault(doc, set()).add(policy)
    for trace in broker_traces:
        for doc in trace.forbidden_documents:
            forbidden.setdefault(doc, []).append(trace)

    for doc in sorted(set(forbidden) & set(sources)):
        required_ids = _rule_ids(sources[doc])
        forbidden_ids = _rule_ids(forbidden[doc])
        issues.append(DossierIssue(
            REQUIREMENT_CONFLICT, BLOCKING,
            f"{doc} is required by {required_ids} but forbidden by {forbidden_ids}",
            document_type=doc,
            subject_type="document",
            subject_id=doc,
            versions=tuple(sorted({
                trace.version
                for trace in (*sources[doc], *forbidden[doc])
            })),
        ))

    selections: list[DocumentSelection] = []
    used_artifacts: set[DocumentArtifact] = set()
    for doc in sorted(sources):
        selection = _select_document(
            context, doc, tuple(sorted(sources[doc], key=_trace_sort_key)),
            doc in batch_specific, frozenset(document_policies.get(doc, ())),
            artifacts, at, issues,
        )
        selections.append(selection)
        if selection.artifact is not None:
            used_artifacts.add(selection.artifact)

    license_selections: list[LicenseSelection] = []
    for license_type in sorted(license_sources):
        selection = _select_license(
            context, license_type,
            tuple(sorted(license_sources[license_type], key=_trace_sort_key)),
            licenses, at, issues,
        )
        license_selections.append(selection)

    for doc, traces_for_doc in sorted(forbidden.items()):
        if doc in sources:
            continue
        for artifact in artifacts:
            if artifact.document_type != doc:
                continue
            issues.append(DossierIssue(
                REQUIREMENT_CONFLICT, BLOCKING,
                f"{doc} is supplied but forbidden by {_rule_ids(traces_for_doc)}",
                document_type=doc,
                subject_type="document",
                subject_id=doc,
                artifact_id=artifact.artifact_id,
                versions=(artifact.version,),
            ))

    for artifact in sorted(artifacts, key=lambda a: (a.document_type, a.artifact_id, a.version)):
        if artifact in used_artifacts:
            continue
        if artifact.document_type in sources or artifact.document_type in forbidden:
            # Invalid and lower-priority candidates are already reported when the
            # document is required.  Valid duplicates receive a warning there.
            continue
        issues.append(DossierIssue(
            OBSOLETE_DOCUMENT, WARNING,
            f"{artifact.document_type} is supplied but not required at {_iso(at)}",
            document_type=artifact.document_type,
            subject_type="document",
            subject_id=artifact.document_type,
            artifact_id=artifact.artifact_id,
            versions=(artifact.version,),
        ))

    return _finalize(
        context, assembled, customs_traces, broker_traces,
        tuple(selections), tuple(license_selections),
        tuple(sorted(included_ids)),
        tuple(a for a in artifacts if a not in used_artifacts and a.document_type not in sources and a.document_type not in forbidden),
        issues,
    )


def replay_declarations(
    submissions: Iterable[DeclarationSubmission],
    requirements: Iterable[RequirementVersion] = (),
    artifacts: Iterable[DocumentArtifact] = (),
    broker_rules: Iterable[BrokerRuleVersion] = (),
    licenses: Iterable[LicenseRecord] = (),
) -> list[ReplayedDeclaration]:
    """Replay every submission against the rules effective when it was filed."""

    rows = sorted(tuple(submissions), key=lambda s: (s.revision, _iso(s.context.event_time)))
    if not rows:
        return []
    declaration_id = rows[0].declaration_id
    expected_revision = 1
    previous: Dossier | None = None
    result: list[ReplayedDeclaration] = []

    by_artifact_id: dict[str, list[DocumentArtifact]] = {}
    for artifact in artifacts:
        by_artifact_id.setdefault(artifact.artifact_id, []).append(artifact)

    for submission in rows:
        if submission.declaration_id != declaration_id:
            raise ValueError("cannot replay submissions for different declaration ids")
        if submission.revision != expected_revision:
            raise ValueError(f"expected revision {expected_revision}, found {submission.revision}")
        if previous is not None and utc(submission.context.event_time) < utc(previous.context.event_time):
            raise ValueError("submission event time moved backward")
        if submission.revision == 1 and submission.external_rejection_codes:
            raise ValueError("revision 1 cannot carry an external rejection")

        resolved: list[DocumentArtifact] = []
        extra_issues: list[DossierIssue] = []
        for artifact_id in sorted(submission.artifact_ids):
            candidates = by_artifact_id.get(artifact_id, [])
            if not candidates:
                extra_issues.append(DossierIssue(
                    UNKNOWN_DOCUMENT, BLOCKING,
                    f"artifact {artifact_id} is not present in the immutable artifact catalog",
                    subject_type="document",
                    subject_id=artifact_id,
                    artifact_id=artifact_id,
                ))
            elif any(
                sum(1 for candidate in candidates if candidate.version == version) > 1
                and len({candidate.sha256 for candidate in candidates if candidate.version == version}) > 1
                for version in {candidate.version for candidate in candidates}
            ):
                raise ValueError(f"artifact id {artifact_id} has inconsistent hashes for one version")
            else:
                resolved.extend(candidates)

        dossier = assemble_dossier(
            submission.context, requirements, resolved, broker_rules, licenses,
            assembled_at=submission.context.event_time,
            included_artifact_ids=submission.artifact_ids,
            allow_unknown_artifact_ids=True,
        )
        if extra_issues:
            dossier = _with_extra_issues(
                dossier, extra_issues,
                tuple(sorted(submission.artifact_ids)),
            )

        reason = None
        if previous is not None:
            reason = _resubmission_reason(previous, dossier, submission)
        result.append(ReplayedDeclaration(submission, dossier, reason))
        previous = dossier
        expected_revision += 1

    return result


def _select_customs(context: DossierContext, rules: Iterable[RequirementVersion], at: datetime) -> tuple[RuleTrace, ...]:
    traces: list[RuleTrace] = []
    for rule in rules:
        if not _active(rule.effective_from, rule.effective_to, at):
            continue
        if not all(_matches_context(context, rule.destination_country, rule.origin_country, rule.product_class, WILDCARD)):
            continue
        traces.append(RuleTrace(
            CUSTOMS_KIND, rule.requirement_id, rule.version,
            rule.destination_country, rule.origin_country, rule.product_class, WILDCARD,
            tuple(sorted(rule.required_documents)), (),
            tuple(sorted(rule.batch_specific_documents)),
            tuple(sorted(rule.required_license_types)),
            tuple(sorted(rule.document_rules.items())),
            rule.effective_from, rule.effective_to, rule.priority,
        ))
    return tuple(sorted(traces, key=_trace_sort_key))


def _select_broker(context: DossierContext, rules: Iterable[BrokerRuleVersion], at: datetime) -> tuple[RuleTrace, ...]:
    traces: list[RuleTrace] = []
    for rule in rules:
        if not _active(rule.effective_from, rule.effective_to, at):
            continue
        if not all(_matches_context(context, rule.destination_country, rule.origin_country, rule.product_class, rule.broker_id)):
            continue
        traces.append(RuleTrace(
            BROKER_KIND, rule.rule_id, rule.version,
            rule.destination_country, rule.origin_country, rule.product_class,
            rule.broker_id,
            tuple(sorted(rule.required_documents)),
            tuple(sorted(rule.forbidden_documents)),
            tuple(sorted(rule.batch_specific_documents)),
            tuple(sorted(rule.required_license_types)),
            tuple(sorted(rule.document_rules.items())),
            rule.effective_from, rule.effective_to, rule.priority,
        ))
    return tuple(sorted(traces, key=_trace_sort_key))


def _resolve_rule_overlaps(context: DossierContext, traces: tuple[RuleTrace, ...], issues: list[DossierIssue]) -> tuple[RuleTrace, ...]:
    result: list[RuleTrace] = []
    by_identity: dict[tuple[str, str], list[RuleTrace]] = {}
    for trace in traces:
        by_identity.setdefault((trace.kind, trace.rule_id), []).append(trace)
    for (kind, rule_id), rows in sorted(by_identity.items()):
        ranked = sorted(rows, key=lambda trace: (-_rule_score(context, trace), -trace.priority, trace.version))
        best_score = _rule_score(context, ranked[0])
        best_priority = ranked[0].priority
        best = [
            trace for trace in ranked
            if _rule_score(context, trace) == best_score and trace.priority == best_priority
        ]
        if len(best) > 1:
            versions = tuple(sorted(trace.version for trace in best))
            issues.append(DossierIssue(
                RULE_VERSION_CONFLICT, BLOCKING,
                f"{kind} rule {rule_id} has multiple effective versions: {', '.join(versions)}",
                rule_id=rule_id,
                subject_type="rule",
                subject_id=rule_id,
                versions=versions,
            ))
        else:
            result.append(best[0])
    return tuple(sorted(result, key=_trace_sort_key))


def _rule_score(context: DossierContext, trace: RuleTrace) -> int:
    fields = (
        (context.destination_country, trace.destination_country),
        (context.origin_country, trace.origin_country),
        (context.product_class, trace.product_class),
        (context.broker_id, trace.broker_id),
    )
    return sum(1 for actual, allowed in fields if actual != WILDCARD and allowed == actual)


def _matches_context(context: DossierContext, destination: str, origin: str, product: str, broker: str) -> tuple[bool, bool, bool, bool]:
    return (
        _matches(context.destination_country, destination),
        _matches(context.origin_country, origin),
        _matches(context.product_class, product),
        broker == WILDCARD or _matches(context.broker_id, broker),
    )


def _matches(actual: str, allowed: str) -> bool:
    return allowed == WILDCARD or actual == WILDCARD or actual == allowed


def _active(start: datetime, end: datetime | None, at: datetime) -> bool:
    return utc(start) <= at and (end is None or at < utc(end))


def _select_document(context, document_type, sources, batch_specific, required_policies, artifacts, at, issues):
    findings: list[CandidateFinding] = []
    valid: list[DocumentArtifact] = []

    if batch_specific and context.batch_id == WILDCARD:
        issues.append(DossierIssue(
            BATCH_NOT_IDENTIFIED, BLOCKING,
            f"batch must be identified before batch-specific {document_type} can be assembled",
            document_type=document_type,
            subject_type="document",
            subject_id=document_type,
        ))

    for artifact in artifacts:
        if artifact.document_type != document_type:
            continue
        artifact_findings = _document_findings(context, artifact, at, batch_specific)
        if not artifact_findings:
            valid.append(artifact)
        for finding in artifact_findings:
            findings.append(finding)
            issues.append(DossierIssue(
                finding.code, BLOCKING,
                finding.message,
                document_type=document_type,
                subject_type="document",
                subject_id=document_type,
                artifact_id=artifact.artifact_id,
                versions=(artifact.version,),
            ))

    valid = _dedupe_identities(valid)
    ranked = sorted(
        valid,
        key=lambda a: (-_document_score(context, a), -utc(a.issued_at).timestamp(), a.artifact_id, a.version),
    )

    if not ranked:
        issues.append(DossierIssue(
            MISSING_DOCUMENT, BLOCKING,
            f"no effective {document_type} matches declaration context at {_iso(at)}",
            document_type=document_type,
            subject_type="document",
            subject_id=document_type,
        ))
        return DocumentSelection(document_type, "missing", None, sources, tuple(findings))

    winner = ranked[0]
    top = [
        a for a in ranked
        if _document_score(context, a) == _document_score(context, winner)
        and utc(a.issued_at) == utc(winner.issued_at)
    ]
    distinct = {(a.artifact_id, a.version, a.sha256) for a in top}
    if len(distinct) > 1:
        identities = tuple(sorted({(a.artifact_id, a.version) for a in top}))
        issues.append(DossierIssue(
            CONFLICTING_DOCUMENTS, BLOCKING,
            f"multiple equally current versions of {document_type} are available: {identities}",
            document_type=document_type,
            subject_type="document",
            subject_id=document_type,
            versions=tuple(sorted({a.version for a in top})),
        ))
        return DocumentSelection(document_type, "conflict", None, sources, tuple(findings), identities)

    missing_policies = required_policies - set(_artifact_policies(context, winner))
    if missing_policies:
        issues.append(DossierIssue(
            DOCUMENT_CONTEXT_MISMATCH, BLOCKING,
            f"selected {document_type} lacks required policy fields: {sorted(missing_policies)}",
            document_type=document_type,
            subject_type="document",
            subject_id=document_type,
            artifact_id=winner.artifact_id,
            versions=(winner.version,),
        ))
        return DocumentSelection(document_type, "conflict", None, sources, tuple(findings))

    for other in ranked[1:]:
        issues.append(DossierIssue(
            MULTIPLE_APPLICABLE_DOCUMENTS, WARNING,
            f"{other.artifact_id} version {other.version} also applies; {winner.artifact_id} version {winner.version} was selected",
            document_type=document_type,
            subject_type="document",
            subject_id=document_type,
            artifact_id=other.artifact_id,
            versions=(other.version,),
        ))

    return DocumentSelection(document_type, "selected", winner, sources, tuple(findings))


def _artifact_policies(context: DossierContext, artifact: DocumentArtifact) -> list[str]:
    policies = []
    if artifact.batch_id == context.batch_id and context.batch_id != WILDCARD:
        policies.append("batch_specific")
    if artifact.product_class == context.product_class and context.product_class != WILDCARD:
        policies.append("product_specific")
    if artifact.origin_country == context.origin_country and context.origin_country != WILDCARD:
        policies.append("origin_specific")
    if artifact.destination_country == context.destination_country and context.destination_country != WILDCARD:
        policies.append("destination_specific")
    if artifact.broker_id == context.broker_id and context.broker_id != WILDCARD:
        policies.append("broker_specific")
    return policies


def _document_findings(context: DossierContext, artifact: DocumentArtifact, at: datetime, batch_specific: bool) -> list[CandidateFinding]:
    lifecycle = []
    scope_problems = []

    if utc(artifact.issued_at) > at:
        lifecycle.append((FUTURE_DOCUMENT, f"issued at {_iso(artifact.issued_at)}, after declaration at {_iso(at)}"))
    start = artifact.valid_from or artifact.issued_at
    if utc(start) > at:
        lifecycle.append((NOT_YET_VALID_DOCUMENT, f"not valid until {_iso(start)}"))
    if artifact.valid_to is not None and at >= utc(artifact.valid_to):
        lifecycle.append((EXPIRED_DOCUMENT, f"expired at {_iso(artifact.valid_to)}"))
    if artifact.superseded_at is not None and at >= utc(artifact.superseded_at):
        lifecycle.append((SUPERSEDED_DOCUMENT, f"superseded at {_iso(artifact.superseded_at)}"))
    if artifact.revoked_at is not None and at >= utc(artifact.revoked_at):
        lifecycle.append((REVOKED_DOCUMENT, f"revoked at {_iso(artifact.revoked_at)}"))

    for label, actual, allowed in (
        ("destination", context.destination_country, artifact.destination_country),
        ("origin", context.origin_country, artifact.origin_country),
        ("product", context.product_class, artifact.product_class),
        ("broker", context.broker_id, artifact.broker_id),
    ):
        if not _matches(actual, allowed):
            scope_problems.append(f"{label}={actual} does not match {allowed}")

    batch_code = ""
    if batch_specific and artifact.batch_id != context.batch_id:
        batch_code = BATCH_MISMATCH
        scope_problems.append(f"batch-specific document requires batch {context.batch_id}, got {artifact.batch_id}")
    elif context.batch_id != WILDCARD and artifact.batch_id not in (WILDCARD, context.batch_id):
        batch_code = BATCH_MISMATCH
        scope_problems.append(f"document batch {artifact.batch_id} does not match {context.batch_id}")

    if scope_problems:
        lifecycle.append((batch_code or DOCUMENT_CONTEXT_MISMATCH, "; ".join(scope_problems)))
    return [
        CandidateFinding(artifact.artifact_id, artifact.version, code, message)
        for code, message in lifecycle
    ]


def _document_score(context: DossierContext, artifact: DocumentArtifact) -> int:
    flags = (
        context.batch_id != WILDCARD and artifact.batch_id == context.batch_id,
        context.product_class != WILDCARD and artifact.product_class == context.product_class,
        context.origin_country != WILDCARD and artifact.origin_country == context.origin_country,
        context.destination_country != WILDCARD and artifact.destination_country == context.destination_country,
        context.broker_id != WILDCARD and artifact.broker_id == context.broker_id,
    )
    return sum(1 for flag in flags if flag)


def _select_license(context, license_type, sources, licenses, at, issues):
    findings: list[CandidateFinding] = []
    valid: list[LicenseRecord] = []

    if not context.license_holder:
        issues.append(DossierIssue(
            LICENSE_HOLDER_MISSING, BLOCKING,
            f"license holder must be identified to evaluate {license_type}",
            license_type=license_type,
            subject_type="license",
            subject_id=license_type,
        ))

    for license_ in licenses:
        if license_.license_type != license_type:
            continue
        license_findings = _license_findings(context, license_, at)
        if not license_findings:
            valid.append(license_)
        for finding in license_findings:
            findings.append(finding)
            issues.append(DossierIssue(
                finding.code, BLOCKING,
                finding.message,
                license_type=license_type,
                subject_type="license",
                subject_id=license_type,
                artifact_id=license_.license_id,
                versions=(license_.version,),
            ))

    valid = _dedupe_license_identities(valid)
    ranked = sorted(
        valid,
        key=lambda item: (-_license_score(context, item), -utc(item.issued_at).timestamp(), item.license_id, item.version),
    )

    if not ranked:
        issues.append(DossierIssue(
            MISSING_LICENSE, BLOCKING,
            f"no effective {license_type} license matches declaration context at {_iso(at)}",
            license_type=license_type,
            subject_type="license",
            subject_id=license_type,
        ))
        return LicenseSelection(license_type, "missing", None, sources, tuple(findings))

    winner = ranked[0]
    top = [
        item for item in ranked
        if _license_score(context, item) == _license_score(context, winner)
        and utc(item.issued_at) == utc(winner.issued_at)
    ]
    distinct = {(item.license_id, item.version) for item in top}
    if len(distinct) > 1:
        identities = tuple(sorted(distinct))
        issues.append(DossierIssue(
            CONFLICTING_LICENSES, BLOCKING,
            f"multiple equally current {license_type} licenses are available: {identities}",
            license_type=license_type,
            subject_type="license",
            subject_id=license_type,
            versions=tuple(sorted({item.version for item in top})),
        ))
        return LicenseSelection(license_type, "conflict", None, sources, tuple(findings), identities)

    for other in ranked[1:]:
        issues.append(DossierIssue(
            MULTIPLE_APPLICABLE_LICENSES, WARNING,
            f"{other.license_id} version {other.version} also applies; {winner.license_id} version {winner.version} was selected",
            license_type=license_type,
            subject_type="license",
            subject_id=license_type,
            artifact_id=other.license_id,
            versions=(other.version,),
        ))
    return LicenseSelection(license_type, "selected", winner, sources, tuple(findings))


def _license_findings(context: DossierContext, license_: LicenseRecord, at: datetime) -> list[CandidateFinding]:
    findings = []
    if utc(license_.issued_at) > at:
        findings.append((FUTURE_LICENSE, f"issued at {_iso(license_.issued_at)}, after declaration at {_iso(at)}"))
    if utc(license_.valid_from) > at:
        findings.append((LICENSE_NOT_YET_VALID, f"not valid until {_iso(license_.valid_from)}"))
    if license_.valid_to is not None and at >= utc(license_.valid_to):
        findings.append((EXPIRED_LICENSE, f"expired at {_iso(license_.valid_to)}"))
    if license_.suspended_at is not None and at >= utc(license_.suspended_at):
        findings.append((SUSPENDED_LICENSE, f"suspended at {_iso(license_.suspended_at)}"))
    if license_.superseded_at is not None and at >= utc(license_.superseded_at):
        findings.append((SUPERSEDED_LICENSE, f"superseded at {_iso(license_.superseded_at)}"))
    if license_.revoked_at is not None and at >= utc(license_.revoked_at):
        findings.append((REVOKED_LICENSE, f"revoked at {_iso(license_.revoked_at)}"))

    scope_problems = []
    if context.license_holder and license_.holder != context.license_holder:
        scope_problems.append(f"holder {license_.holder} does not match {context.license_holder}")
    if not _matches(context.destination_country, license_.jurisdiction):
        scope_problems.append(f"jurisdiction {license_.jurisdiction} does not match {context.destination_country}")
    if not _matches(context.product_class, license_.product_class):
        scope_problems.append(f"product {license_.product_class} does not match {context.product_class}")
    if not _matches(context.origin_country, license_.origin_country):
        scope_problems.append(f"origin {license_.origin_country} does not match {context.origin_country}")
    if scope_problems:
        findings.append((LICENSE_SCOPE_MISMATCH, "; ".join(scope_problems)))
    return [
        CandidateFinding(license_.license_id, license_.version, code, message)
        for code, message in findings
    ]


def _license_score(context: DossierContext, license_: LicenseRecord) -> int:
    flags = (
        context.destination_country != WILDCARD and license_.jurisdiction == context.destination_country,
        context.product_class != WILDCARD and license_.product_class == context.product_class,
        context.origin_country != WILDCARD and license_.origin_country == context.origin_country,
    )
    return sum(1 for flag in flags if flag)


def _resubmission_reason(previous: Dossier, current: Dossier, submission: DeclarationSubmission) -> ResubmissionReason:
    codes: set[str] = set()
    explanations: list[str] = []

    for rejection_code in sorted(submission.external_rejection_codes):
        codes.add(EXTERNAL_REJECTION)
        explanations.append(
            f"customs rejected revision {submission.revision - 1}: {rejection_code}"
        )

    prior_blocking = [issue for issue in previous.issues if issue.severity == BLOCKING]
    if prior_blocking:
        codes.add(PREVIOUS_DOSSIER_INCOMPLETE)
        prior_codes = tuple(sorted({issue.code for issue in prior_blocking}))
        codes.update(prior_codes)
        explanations.append(
            f"revision {submission.revision - 1} was incomplete: {', '.join(prior_codes)}"
        )

    changed_context = _changed_context(previous.context, current.context)
    if changed_context:
        codes.add(CONTEXT_CHANGED)
        explanations.append("context changed: " + ", ".join(f"{name} {old} -> {new}" for name, old, new in changed_context))

    changed_rules = _changed_rules(previous, current)
    broker_changes = [row for row in changed_rules if row[0] == BROKER_KIND]
    customs_changes = [row for row in changed_rules if row[0] == CUSTOMS_KIND]
    if customs_changes:
        codes.add(RULE_VERSION_CHANGED)
        explanations.append("customs rule versions changed: " + _format_rule_changes(customs_changes))
    if broker_changes:
        codes.add(BROKER_RULE_VERSION_CHANGED)
        explanations.append("broker rule versions changed: " + _format_rule_changes(broker_changes))

    added, removed, replaced = _changed_documents(previous, current)
    if added or removed or replaced:
        codes.add(DOCUMENTS_CHANGED)
        details = []
        if added:
            details.append(f"added {sorted(added)}")
        if removed:
            details.append(f"removed {sorted(removed)}")
        if replaced:
            details.append(f"replaced {replaced}")
        explanations.append("; ".join(details))

    changed_licenses = _changed_licenses(previous, current)
    if changed_licenses:
        codes.add(LICENSE_CHANGED)
        explanations.append(f"selected licenses changed: {changed_licenses}")

    if not codes:
        codes.add(UNCHANGED_RESUBMISSION)
        explanations.append("no rule, context, document or license change explains the resubmission")

    current_blocking = tuple(sorted({issue.code for issue in current.issues if issue.severity == BLOCKING}))
    if current_blocking:
        explanations.append(f"revision {submission.revision} still has blocking issues: {', '.join(current_blocking)}")
    else:
        explanations.append(f"revision {submission.revision} is complete")

    return ResubmissionReason(
        submission.revision,
        tuple(sorted(codes)),
        tuple(explanations),
        tuple(changed_context),
        tuple(sorted(added)),
        tuple(sorted(removed)),
        tuple(replaced),
        tuple(changed_rules),
        tuple(changed_licenses),
    )


def _changed_context(old: DossierContext, new: DossierContext) -> list[tuple[str, str, str]]:
    fields_ = (
        ("destination_country", old.destination_country, new.destination_country),
        ("origin_country", old.origin_country, new.origin_country),
        ("product_class", old.product_class, new.product_class),
        ("broker_id", old.broker_id, new.broker_id),
        ("batch_id", old.batch_id, new.batch_id),
        ("license_holder", old.license_holder or "", new.license_holder or ""),
        ("event_time", _iso(old.event_time), _iso(new.event_time)),
    )
    return [(name, old_value, new_value) for name, old_value, new_value in fields_ if old_value != new_value]


def _rule_version_map(dossier: Dossier) -> dict[tuple[str, str], str]:
    out = {}
    for trace in (*dossier.requirement_rules, *dossier.broker_rules):
        out[(trace.kind, trace.rule_id)] = trace.version
    return out


def _changed_rules(old: Dossier, new: Dossier) -> list[tuple[str, str, str, str]]:
    old_map = _rule_version_map(old)
    new_map = _rule_version_map(new)
    changes = []
    for key in sorted(set(old_map) | set(new_map)):
        old_value = old_map.get(key, "<absent>")
        new_value = new_map.get(key, "<absent>")
        if old_value != new_value:
            changes.append((key[0], key[1], old_value, new_value))
    return changes


def _selected_documents(dossier: Dossier) -> dict[str, tuple[str, str, str] | None]:
    out = {}
    for selection in dossier.document_selections:
        out[selection.document_type] = (
            (selection.artifact.artifact_id, selection.artifact.version, selection.artifact.sha256)
            if selection.artifact is not None else None
        )
    return out


def _document_ref(value: tuple[str, str, str] | None) -> str | None:
    if value is None:
        return None
    return f"{value[0]}@v{value[1]}"


def _changed_documents(old: Dossier, new: Dossier):
    old_supplied = set(old.submitted_artifact_ids)
    new_supplied = set(new.submitted_artifact_ids)
    added = new_supplied - old_supplied
    removed = old_supplied - new_supplied
    old_selected = _selected_documents(old)
    new_selected = _selected_documents(new)
    replaced = []
    for doc in sorted(set(old_selected) & set(new_selected)):
        before = _document_ref(old_selected[doc])
        after = _document_ref(new_selected[doc])
        if before != after:
            replaced.append((doc, before, after))
    return added, removed, tuple(replaced)



def _license_ref(license_: LicenseRecord | None) -> str | None:
    if license_ is None:
        return None
    return f"{license_.license_id}@v{license_.version}"


def _changed_licenses(old: Dossier, new: Dossier) -> list[tuple[str, str | None, str | None]]:
    old_map = {
        selection.license_type: _license_ref(selection.license)
        for selection in old.license_selections
    }
    new_map = {
        selection.license_type: _license_ref(selection.license)
        for selection in new.license_selections
    }
    out = []
    for license_type in sorted(set(old_map) | set(new_map)):
        if old_map.get(license_type) != new_map.get(license_type):
            out.append((license_type, old_map.get(license_type), new_map.get(license_type)))
    return out


def _finalize(context, assembled_at, customs, broker, documents, licenses, submitted_ids, unused, issues) -> Dossier:
    unique_issues = tuple(sorted({issue.key(): issue for issue in issues}.values(), key=_issue_sort_key))
    dossier = Dossier(
        context=context,
        assembled_at=utc(assembled_at),
        requirement_rules=customs,
        broker_rules=broker,
        document_selections=documents,
        license_selections=licenses,
        submitted_artifact_ids=submitted_ids,
        unused_artifacts=unused,
        issues=unique_issues,
        complete=not any(issue.severity == BLOCKING for issue in unique_issues),
        manifest_digest="",
    )
    return replace(dossier, manifest_digest=_manifest_digest(dossier))


def _with_extra_issues(
    dossier: Dossier,
    extra: Iterable[DossierIssue],
    submitted_ids: tuple[str, ...] | None = None,
) -> Dossier:
    issues = tuple(sorted({*dossier.issues, *extra}, key=_issue_sort_key))
    updated = replace(
        dossier,
        issues=issues,
        submitted_artifact_ids=submitted_ids if submitted_ids is not None else dossier.submitted_artifact_ids,
        complete=not any(issue.severity == BLOCKING for issue in issues),
    )
    return replace(updated, manifest_digest=_manifest_digest(updated))


def _manifest_digest(dossier: Dossier) -> str:
    payload = {
        "context": dossier.context.canonical(),
        "assembled_at": _iso(dossier.assembled_at),
        "submitted_artifact_ids": list(dossier.submitted_artifact_ids),
        "customs_rules": [trace.canonical() for trace in dossier.requirement_rules],
        "broker_rules": [trace.canonical() for trace in dossier.broker_rules],
        "documents": [
            {
                "document_type": selection.document_type,
                "status": selection.status,
                "artifact": None if selection.artifact is None else {
                    "artifact_id": selection.artifact.artifact_id,
                    "version": selection.artifact.version,
                    "sha256": selection.artifact.sha256,
                },
                "conflicting": selection.conflicting_artifacts,
                "sources": [(trace.kind, trace.rule_id, trace.version) for trace in selection.sources],
            }
            for selection in dossier.document_selections
        ],
        "licenses": [
            {
                "license_type": selection.license_type,
                "status": selection.status,
                "license": None if selection.license is None else {
                    "license_id": selection.license.license_id,
                    "version": selection.license.version,
                },
                "conflicting": selection.conflicting_licenses,
            }
            for selection in dossier.license_selections
        ],
        "issues": [
            [issue.code, issue.severity, issue.message, issue.document_type, issue.license_type,
             issue.rule_id, issue.subject_type, issue.subject_id, issue.artifact_id, list(issue.versions)]
            for issue in dossier.issues
        ],
        "complete": dossier.complete,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _dedupe_identities(items: list[DocumentArtifact]) -> list[DocumentArtifact]:
    by_identity = {}
    for item in items:
        by_identity.setdefault(item.identity(), item)
    return list(by_identity.values())


def _dedupe_license_identities(items: list[LicenseRecord]) -> list[LicenseRecord]:
    by_identity = {}
    for item in items:
        by_identity.setdefault(item.identity(), item)
    return list(by_identity.values())


def _rule_ids(traces: Iterable[RuleTrace]) -> list[str]:
    return sorted({f"{trace.kind}:{trace.rule_id}@v{trace.version}" for trace in traces})


def _trace_sort_key(trace: RuleTrace) -> tuple:
    return (
        trace.kind, trace.rule_id, trace.version,
        trace.destination_country, trace.origin_country, trace.product_class, trace.broker_id,
        -trace.priority,
    )


def _issue_sort_key(issue: DossierIssue) -> tuple:
    return (issue.code, issue.document_type, issue.license_type, issue.rule_id, issue.artifact_id, issue.message)


def _format_rule_changes(changes) -> str:
    return ", ".join(f"{kind}:{rule_id} {old} -> {new}" for kind, rule_id, old, new in changes)


def _validate_window(start: datetime, end: datetime | None) -> None:
    _aware(start, "effective_from")
    if end is not None:
        _aware(end, "effective_to")
        if utc(end) <= utc(start):
            raise ValueError("effective_to must be after effective_from")


def _aware(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return utc(value).isoformat()


build_customs_dossier = assemble_dossier
replay_customs_declarations = replay_declarations
