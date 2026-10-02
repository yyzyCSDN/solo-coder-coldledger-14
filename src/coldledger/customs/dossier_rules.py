from __future__ import annotations
from dataclasses import dataclass
from datetime import date
from enum import Enum
from threading import RLock


@dataclass(frozen=True)
class Facts:
    destination_country: str
    product_class: str
    origin_country: str
    broker_id: str
    license_type: str | None  # license held by the declarant, None if none
    shipment_date: date
    declaration_date: date


class RuleKind(Enum):
    REQUIRE = "REQUIRE"
    WAIVE = "WAIVE"  # e.g. requirement lifted when a license is held


@dataclass(frozen=True)
class Constraint:
    name: str  # "max_age_days" | "original_only" | ...
    value: object


@dataclass(frozen=True)
class RuleVersion:
    """One effective version of a document rule. Immutable once published;
    any change is published as a new version of the same rule_id."""

    rule_id: str
    version: int
    kind: RuleKind
    doc_type: str
    destination_country: str | None = None
    product_class: str | None = None
    origin_country: str | None = None
    broker_id: str | None = None
    license_type: str | None = None
    constraints: tuple[Constraint, ...] = ()
    valid_from: date = date.min  # business effective window
    valid_to: date | None = None  # None = still in force
    recorded_from: date = date.min  # when the store learned this version
    source_ref: str = ""  # regulation / circular citation, for traceability
    note: str = ""

    @property
    def ref(self) -> str:
        return f"{self.rule_id}@v{self.version}"

    def matches(self, facts: Facts) -> bool:
        return (
            (self.destination_country is None or self.destination_country == facts.destination_country)
            and (self.product_class is None or self.product_class == facts.product_class)
            and (self.origin_country is None or self.origin_country == facts.origin_country)
            and (self.broker_id is None or self.broker_id == facts.broker_id)
            and (self.license_type is None or self.license_type == facts.license_type)
        )

    def specificity(self) -> int:
        dims = (self.destination_country, self.product_class, self.origin_country, self.broker_id, self.license_type)
        return sum(d is not None for d in dims)

    def valid_at(self, day: date) -> bool:
        return self.valid_from <= day and (self.valid_to is None or day <= self.valid_to)


class RuleStore:
    """Append-only rule versions. select() picks, per rule_id, the latest-recorded
    version whose validity window covers valid_day. Versions recorded after
    recorded_day are invisible, which is what makes historical replay exact;
    an earlier version stays visible for valid_days its successor does not cover."""

    def __init__(self) -> None:
        self._versions: list[RuleVersion] = []
        self._lock = RLock()

    def publish(self, rv: RuleVersion) -> RuleVersion:
        with self._lock:
            if any(v.rule_id == rv.rule_id and v.version == rv.version for v in self._versions):
                raise ValueError(f"rule version already exists: {rv.ref}")
            self._versions.append(rv)
            return rv

    def get_by_ref(self, ref: str) -> RuleVersion:
        rule_id, _, ver = ref.rpartition("@v")
        with self._lock:
            for v in self._versions:
                if v.rule_id == rule_id and v.version == int(ver):
                    return v
        raise KeyError(ref)

    def select(self, valid_day: date, recorded_day: date) -> list[RuleVersion]:
        with self._lock:
            candidates: dict[str, list[RuleVersion]] = {}
            for v in self._versions:
                if v.recorded_from <= recorded_day and v.valid_at(valid_day):
                    candidates.setdefault(v.rule_id, []).append(v)
            return [max(rows, key=lambda v: (v.recorded_from, v.version)) for rows in candidates.values()]
