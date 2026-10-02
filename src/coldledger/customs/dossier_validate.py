from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date

from .dossier import Dossier, Finding, FindingKind

# fields that must agree across all submitted documents
CROSS_CHECK_FIELDS = ("origin_country", "hs_code", "net_weight_kg")


@dataclass(frozen=True)
class Document:
    doc_type: str
    issue_date: date
    expiry_date: date | None = None
    is_original: bool = True
    fields: dict = field(default_factory=dict)


def validate(dossier: Dossier, documents: list[Document] | tuple[Document, ...]) -> list[Finding]:
    findings: list[Finding] = list(dossier.conflicts)
    by_type: dict[str, list[Document]] = {}
    for d in documents:
        by_type.setdefault(d.doc_type, []).append(d)
    for item in dossier.items:
        if not item.required:
            continue
        docs = by_type.get(item.doc_type, [])
        if not docs:
            findings.append(Finding(
                FindingKind.MISSING,
                f"缺少单证 {item.doc_type}(要求来源: {', '.join(item.required_by)})",
                rule_refs=item.required_by,
                doc_types=(item.doc_type,),
                remediation="补交该单证后重新申报",
            ))
            continue
        doc = docs[0]
        for c in item.constraints:
            if c.name == "max_age_days":
                age = (dossier.facts.shipment_date - doc.issue_date).days
                if age < 0 or age > c.value:
                    findings.append(Finding(
                        FindingKind.EXPIRED,
                        f"{item.doc_type} 签发日 {doc.issue_date} 距起运日 {dossier.facts.shipment_date} 为 {age} 天, "
                        f"超出 {c.value} 天限制(来源: {', '.join(item.required_by)})",
                        rule_refs=item.required_by,
                        doc_types=(item.doc_type,),
                        remediation="重新签发该单证",
                    ))
            elif c.name == "original_only" and c.value and not doc.is_original:
                findings.append(Finding(
                    FindingKind.CONSTRAINT_VIOLATION,
                    f"{item.doc_type} 须为正本, 提交的是副本(来源: {', '.join(item.required_by)})",
                    rule_refs=item.required_by,
                    doc_types=(item.doc_type,),
                    remediation="补交正本单证",
                ))
        if doc.expiry_date is not None and doc.expiry_date < dossier.facts.shipment_date:
            findings.append(Finding(
                FindingKind.EXPIRED,
                f"{item.doc_type} 有效期至 {doc.expiry_date}, 早于起运日 {dossier.facts.shipment_date}",
                rule_refs=item.required_by,
                doc_types=(item.doc_type,),
                remediation="换发有效期覆盖起运日的单证",
            ))
    for field_name in CROSS_CHECK_FIELDS:
        seen: dict[object, list[str]] = {}
        for d in documents:
            if field_name in d.fields:
                seen.setdefault(d.fields[field_name], []).append(d.doc_type)
        if len(seen) > 1:
            detail = "; ".join(f"{k}({', '.join(sorted(v))})" for k, v in sorted(seen.items(), key=lambda x: str(x[0])))
            findings.append(Finding(
                FindingKind.DOC_MISMATCH,
                f"字段 {field_name} 在单证间不一致: {detail}",
                doc_types=tuple(sorted({t for v in seen.values() for t in v})),
                remediation="更正单证使其一致, 或附更正说明",
            ))
    return findings
