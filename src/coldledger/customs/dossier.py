from __future__ import annotations
from dataclasses import dataclass
from datetime import date
from enum import Enum

from .dossier_rules import Constraint, Facts, RuleKind, RuleStore, RuleVersion


class FindingKind(Enum):
    MISSING = "缺件"
    EXPIRED = "证件失效"
    CONSTRAINT_VIOLATION = "单证不满足约束"
    RULE_CONFLICT = "规则冲突"
    DOC_MISMATCH = "单证互相矛盾"
    STALE_RULESET = "套用非生效版本的要求"
    RESUBMIT = "需要重新提交"


@dataclass(frozen=True)
class Finding:
    kind: FindingKind
    message: str
    rule_refs: tuple[str, ...] = ()
    doc_types: tuple[str, ...] = ()
    remediation: str = ""


@dataclass(frozen=True)
class DossierItem:
    doc_type: str
    constraints: tuple[Constraint, ...]
    required_by: tuple[str, ...]  # rule version refs, the traceability anchor
    waived_by: tuple[str, ...] = ()
    required: bool = True


@dataclass(frozen=True)
class Dossier:
    facts: Facts
    as_of_valid: date  # which day's effective rules were used
    as_of_recorded: date  # which day's recorded knowledge was used
    items: tuple[DossierItem, ...]
    conflicts: tuple[Finding, ...] = ()

    @property
    def required_items(self) -> tuple[DossierItem, ...]:
        return tuple(i for i in self.items if i.required)


def _refs(rules: tuple[RuleVersion, ...]) -> str:
    return ", ".join(r.ref for r in rules)


def _fmt_constraints(cs: tuple[Constraint, ...]) -> str:
    return ", ".join(f"{c.name}={c.value}" for c in cs) if cs else "无附加约束"


def _merge_constraints(reqs: tuple[RuleVersion, ...]) -> tuple[Constraint, ...]:
    merged: dict[str, object] = {}
    for r in reqs:
        for c in r.constraints:
            if c.name not in merged:
                merged[c.name] = c.value
            elif c.name == "max_age_days":
                merged[c.name] = min(merged[c.name], c.value)  # stricter wins
            elif c.name == "original_only":
                merged[c.name] = bool(merged[c.name]) or bool(c.value)
    return tuple(Constraint(name, merged[name]) for name in sorted(merged))


def assemble(store: RuleStore, facts: Facts, as_of_valid: date, as_of_recorded: date) -> Dossier:
    """Pure function: same (store, facts, as_of_valid, as_of_recorded) always
    yields the same dossier, so any dossier can be replayed and audited."""
    selected = [rv for rv in store.select(as_of_valid, as_of_recorded) if rv.matches(facts)]
    by_doc: dict[str, list[RuleVersion]] = {}
    for rv in selected:
        by_doc.setdefault(rv.doc_type, []).append(rv)
    items: list[DossierItem] = []
    conflicts: list[Finding] = []
    for doc_type in sorted(by_doc):
        reqs = [r for r in by_doc[doc_type] if r.kind is RuleKind.REQUIRE]
        waivers = [r for r in by_doc[doc_type] if r.kind is RuleKind.WAIVE]
        if not reqs:
            continue
        req_spec = max(r.specificity() for r in reqs)
        top_reqs = tuple(sorted((r for r in reqs if r.specificity() == req_spec), key=lambda r: r.ref))
        waive_spec = max((w.specificity() for w in waivers), default=-1)
        top_waivers = tuple(sorted((w for w in waivers if w.specificity() == waive_spec), key=lambda r: r.ref))
        if top_waivers and waive_spec > req_spec:
            items.append(DossierItem(doc_type, (), (), tuple(w.ref for w in top_waivers), required=False))
            continue
        if top_waivers and waive_spec == req_spec:
            conflicts.append(Finding(
                FindingKind.RULE_CONFLICT,
                f"{doc_type}: 要求 {_refs(top_reqs)} 与豁免 {_refs(top_waivers)} 优先级相同, 无法自动裁定, 已保守保留该要求",
                rule_refs=tuple(r.ref for r in top_reqs + top_waivers),
                doc_types=(doc_type,),
                remediation="由法规专员裁定后, 在规则库中调整版本的维度或生效区间",
            ))
        items.append(DossierItem(doc_type, _merge_constraints(top_reqs), tuple(r.ref for r in top_reqs)))
    return Dossier(facts, as_of_valid, as_of_recorded, tuple(items), tuple(conflicts))


def _required_map(d: Dossier) -> dict[str, DossierItem]:
    return {i.doc_type: i for i in d.items if i.required}


def diff_dossiers(old: Dossier, new: Dossier) -> list[tuple[str, DossierItem | None, DossierItem | None]]:
    """("added"|"removed"|"changed", old_item, new_item) over required items."""
    om, nm = _required_map(old), _required_map(new)
    out: list[tuple[str, DossierItem | None, DossierItem | None]] = []
    for doc_type in sorted(set(om) | set(nm)):
        if doc_type not in om:
            out.append(("added", None, nm[doc_type]))
        elif doc_type not in nm:
            out.append(("removed", om[doc_type], None))
        elif om[doc_type].constraints != nm[doc_type].constraints or om[doc_type].required_by != nm[doc_type].required_by:
            out.append(("changed", om[doc_type], nm[doc_type]))
    return out


def _basis(store: RuleStore, refs: tuple[str, ...]) -> str:
    parts = []
    for ref in refs:
        rv = store.get_by_ref(ref)
        parts.append(f"{ref}(依据 {rv.source_ref}, {rv.valid_from} 起生效)")
    return "; ".join(parts)


def check_stale(dossier: Dossier, store: RuleStore) -> list[Finding]:
    """Detect dossiers assembled from requirement versions that were not in
    effect on the declaration date (the classic stale-checklist failure)."""
    findings: list[Finding] = []
    decl = dossier.facts.declaration_date
    if dossier.as_of_valid != decl:
        findings.append(Finding(
            FindingKind.STALE_RULESET,
            f"dossier 按 {dossier.as_of_valid} 的生效要求组装, 但申报日为 {decl}",
            remediation="按申报日重新组装 dossier",
        ))
    expected = assemble(store, dossier.facts, decl, dossier.as_of_recorded)
    for kind, o, n in diff_dossiers(expected, dossier):
        if kind == "added" and n is not None:
            findings.append(Finding(
                FindingKind.STALE_RULESET,
                f"{n.doc_type} 沿用了申报日不生效的要求, 来源 {_basis(store, n.required_by)}",
                rule_refs=n.required_by,
                doc_types=(n.doc_type,),
                remediation="移除该要求, 或确认是否被其他生效版本覆盖",
            ))
        elif kind == "removed" and o is not None:
            findings.append(Finding(
                FindingKind.STALE_RULESET,
                f"申报日已生效的要求 {o.doc_type} 未包含在 dossier 中, 来源 {_basis(store, o.required_by)}",
                rule_refs=o.required_by,
                doc_types=(o.doc_type,),
                remediation="补充该单证要求",
            ))
        elif kind == "changed" and o is not None and n is not None:
            findings.append(Finding(
                FindingKind.STALE_RULESET,
                f"{n.doc_type} 的要求版本与申报日生效版本不一致: dossier 为 {_fmt_constraints(n.constraints)}({', '.join(n.required_by)}), "
                f"申报日生效版本为 {_fmt_constraints(o.constraints)}({', '.join(o.required_by)})",
                rule_refs=tuple(sorted(set(o.required_by) | set(n.required_by))),
                doc_types=(n.doc_type,),
                remediation="按申报日生效版本重新组装",
            ))
    return findings


def resubmission_check(dossier: Dossier, store: RuleStore, as_of_recorded_now: date) -> list[Finding]:
    """After new rule versions are recorded, decide whether an already-assembled
    dossier must be resubmitted, and explain each delta with its source."""
    new = assemble(store, dossier.facts, dossier.as_of_valid, as_of_recorded_now)
    findings: list[Finding] = []
    for kind, o, n in diff_dossiers(dossier, new):
        if kind == "added" and n is not None:
            findings.append(Finding(
                FindingKind.RESUBMIT,
                f"新增要求 {n.doc_type}({_fmt_constraints(n.constraints)}), 来源 {_basis(store, n.required_by)}",
                rule_refs=n.required_by,
                doc_types=(n.doc_type,),
                remediation="补交该单证后重新提交 dossier",
            ))
        elif kind == "removed" and o is not None:
            findings.append(Finding(
                FindingKind.RESUBMIT,
                f"{o.doc_type} 不再需要: 原要求 {', '.join(o.required_by)} 已被新版本取代或豁免",
                rule_refs=o.required_by,
                doc_types=(o.doc_type,),
                remediation="重新提交时可移除该单证",
            ))
        elif kind == "changed" and o is not None and n is not None:
            findings.append(Finding(
                FindingKind.RESUBMIT,
                f"{o.doc_type} 要求变化: {_fmt_constraints(o.constraints)} → {_fmt_constraints(n.constraints)}, "
                f"来源 {_basis(store, n.required_by)}",
                rule_refs=n.required_by,
                doc_types=(n.doc_type,),
                remediation="按新要求更换单证后重新提交",
            ))
    return findings
