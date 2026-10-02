from __future__ import annotations
from dataclasses import dataclass
from datetime import date

from .dossier import Dossier, Finding, assemble
from .dossier_rules import Facts, RuleStore
from .dossier_validate import Document, validate


@dataclass(frozen=True)
class Declaration:
    """A filed declaration: the dossier, the submitted documents and the
    findings, frozen together with the assembly time points."""

    declaration_id: str
    dossier: Dossier
    documents: tuple[Document, ...]
    findings: tuple[Finding, ...]

    @property
    def facts(self) -> Facts:
        return self.dossier.facts


def file_declaration(
    declaration_id: str,
    store: RuleStore,
    facts: Facts,
    documents: list[Document] | tuple[Document, ...],
    as_of_valid: date | None = None,
    as_of_recorded: date | None = None,
) -> Declaration:
    as_of_valid = as_of_valid or facts.declaration_date
    as_of_recorded = as_of_recorded or date.today()
    dossier = assemble(store, facts, as_of_valid, as_of_recorded)
    findings = tuple(validate(dossier, documents))
    return Declaration(declaration_id, dossier, tuple(documents), findings)


def replay(store: RuleStore, decl: Declaration, as_of_recorded: date) -> tuple[Dossier, list[Finding]]:
    """Re-run assembly and validation for a historical declaration.

    The rule store is append-only and assemble() is pure, so replaying with
    as_of_recorded = decl.dossier.as_of_recorded reproduces the filed result
    exactly (the rules as known then); replaying with a later recorded date
    shows what current knowledge would change for that same declaration."""
    dossier = assemble(store, decl.facts, decl.dossier.as_of_valid, as_of_recorded)
    return dossier, validate(dossier, decl.documents)
