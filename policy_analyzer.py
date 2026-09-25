
from dataclasses import dataclass
from typing import Optional

from ir_nodes import PolicyIR, RuleIR, CheckIR, AndIR, OrIR, NotIR


SUPPORTED_ANOMALIES = frozenset({'conflict', 'shadowing', 'redundancy'})
_PROTOCOL_VALUES = frozenset({'TCP', 'UDP', 'ICMP'})


@dataclass(frozen=True)
class RuleView:
    """An ordered view of a rule for downstream analyzers."""

    index: int
    rule: RuleIR
    condition: object
    action: str


@dataclass(frozen=True)
class AnalysisResult:
    """A relationship proven between two rules in one policy.

    ``earlier_rule`` and ``later_rule`` preserve first-match-wins ordering.
    ``overlap_checks`` contains the actual ``CheckIR`` nodes used as the
    conservative witness constraints; it is empty for an unsupported Boolean
    relationship.  The complete original condition trees remain available in
    ``earlier_condition`` and ``later_condition``.
    """

    anomaly_type: str
    earlier_rule: RuleIR
    later_rule: RuleIR
    earlier_index: int
    later_index: int
    earlier_condition: object
    later_condition: object
    earlier_action: str
    later_action: str
    overlap_checks: tuple[CheckIR, ...] = ()

    @property
    def rule_pair(self) -> tuple[str, str]:
        """Return ``(earlier rule name, later rule name)``."""
        return self.earlier_rule.name, self.later_rule.name


@dataclass(frozen=True)
class AnalysisReport:
    """Analysis output for one ``PolicyIR``."""

    policy: PolicyIR
    rules: tuple[RuleView, ...]
    results: tuple[AnalysisResult, ...]

    @property
    def conflicts(self) -> tuple[AnalysisResult, ...]:
        return tuple(r for r in self.results if r.anomaly_type == 'conflict')

    @property
    def shadowing(self) -> tuple[AnalysisResult, ...]:
        return tuple(r for r in self.results if r.anomaly_type == 'shadowing')

    @property
    def redundancies(self) -> tuple[AnalysisResult, ...]:
        return tuple(r for r in self.results if r.anomaly_type == 'redundancy')

    @property
    def has_anomalies(self) -> bool:
        return bool(self.results)


@dataclass
class _FieldConstraint:
    """Internal constraint summary for one field in an AND condition."""

    ftype: str
    equal: object = None
    excluded: set = None
    lower: object = None
    lower_inclusive: bool = False
    upper: object = None
    upper_inclusive: bool = False

    def __post_init__(self):
        if self.excluded is None:
            self.excluded = set()


class PolicyAnalyzer:
    """Analyze one existing :class:`PolicyIR` without executing packets."""

    def __init__(self, policy_ir: PolicyIR):
        self.policy_ir = policy_ir

    def analyze(self) -> AnalysisReport:
        """Return proven conflicts, shadowing, and redundancies.

        Rules are compared only with later rules, preserving source order.
        Unsupported Boolean shapes are skipped rather than approximated.
        """
        rules = tuple(
            RuleView(i, rule, rule.condition, rule.action)
            for i, rule in enumerate(self.policy_ir.rules)
        )
        results = []

        for later_index, later in enumerate(rules):
            for earlier in rules[:later_index]:
                overlap = self._overlap_checks(
                    earlier.condition, later.condition
                )
                if overlap is None:
                    continue

                covers_later = self._condition_implies(
                    later.condition, earlier.condition
                )
                overlap_checks = tuple(overlap)

                if earlier.action != later.action:
                    results.append(self._result(
                        'conflict', earlier, later, overlap_checks
                    ))

                if covers_later:
                    results.append(self._result(
                        'shadowing', earlier, later, overlap_checks
                    ))
                    if earlier.action == later.action:
                        results.append(self._result(
                            'redundancy', earlier, later, overlap_checks
                        ))

        return AnalysisReport(self.policy_ir, rules, tuple(results))

    def _result(self, anomaly_type: str, earlier: RuleView,
                later: RuleView, overlap_checks: tuple[CheckIR, ...]):
        return AnalysisResult(
            anomaly_type=anomaly_type,
            earlier_rule=earlier.rule,
            later_rule=later.rule,
            earlier_index=earlier.index,
            later_index=later.index,
            earlier_condition=earlier.condition,
            later_condition=later.condition,
            earlier_action=earlier.action,
            later_action=later.action,
            overlap_checks=overlap_checks,
        )

    def _condition_implies(self, source, target) -> bool:
        """Return whether supported condition ``source`` implies ``target``."""
        if self._conditions_equal(source, target):
            return True
        source_checks = self._and_checks(source)
        target_checks = self._and_checks(target)
        if source_checks is None or target_checks is None:
            return False
        source_constraints = self._constraints(source_checks)
        target_constraints = self._constraints(target_checks)
        if source_constraints is None or target_constraints is None:
            return False
        return self._constraints_imply(source_constraints, target_constraints)

    def _overlap_checks(self, first, second) -> Optional[list[CheckIR]]:
        """Return witness checks when two supported conditions can overlap."""
        if self._conditions_equal(first, second):
            checks = self._and_checks(first)
            return [] if checks is None else checks
        first_checks = self._and_checks(first)
        second_checks = self._and_checks(second)
        if first_checks is None or second_checks is None:
            return None
        all_checks = first_checks + second_checks
        constraints = self._constraints(all_checks)
        if constraints is None:
            return None
        return all_checks

    def _and_checks(self, node) -> Optional[list[CheckIR]]:
        if isinstance(node, CheckIR):
            return [node]
        if isinstance(node, AndIR):
            left = self._and_checks(node.left)
            right = self._and_checks(node.right)
            if left is None or right is None:
                return None
            return left + right
        return None

    def _constraints(self, checks: list[CheckIR]):
        constraints = {}
        for check in checks:
            constraint = constraints.setdefault(
                check.field, _FieldConstraint(check.ftype)
            )
            if constraint.ftype != check.ftype:
                return None
            if not self._add_check(constraint, check):
                return None
        if any(not self._is_consistent(c) for c in constraints.values()):
            return None
        return constraints

    def _add_check(self, constraint: _FieldConstraint, check: CheckIR):
        value = check.value
        if check.op == '==':
            if constraint.equal is not None and constraint.equal != value:
                return False
            constraint.equal = value
        elif check.op == '!=':
            constraint.excluded.add(value)
        elif check.op in ('<', '<=', '>', '>='):
            if check.op in ('<', '<='):
                inclusive = check.op == '<='
                if (constraint.upper is None or value < constraint.upper or
                        (value == constraint.upper and
                         inclusive and not constraint.upper_inclusive)):
                    constraint.upper = value
                    constraint.upper_inclusive = inclusive
            else:
                inclusive = check.op == '>='
                if (constraint.lower is None or value > constraint.lower or
                        (value == constraint.lower and
                         inclusive and not constraint.lower_inclusive)):
                    constraint.lower = value
                    constraint.lower_inclusive = inclusive
        else:
            return False
        return True

    def _is_consistent(self, constraint: _FieldConstraint) -> bool:
        if constraint.equal is not None:
            return self._value_satisfies(constraint, constraint.equal)
        if (constraint.lower is not None and constraint.upper is not None and
                (constraint.lower > constraint.upper or
                 (constraint.lower == constraint.upper and
                  not (constraint.lower_inclusive and
                       constraint.upper_inclusive)))):
            return False
        if (constraint.ftype == 'PROTOCOL' and
                constraint.equal is None and
                constraint.lower is None and constraint.upper is None and
                _PROTOCOL_VALUES.issubset(constraint.excluded)):
            return False
        return True

    def _value_satisfies(self, constraint: _FieldConstraint, value) -> bool:
        if value in constraint.excluded:
            return False
        if constraint.lower is not None:
            if value < constraint.lower:
                return False
            if value == constraint.lower and not constraint.lower_inclusive:
                return False
        if constraint.upper is not None:
            if value > constraint.upper:
                return False
            if value == constraint.upper and not constraint.upper_inclusive:
                return False
        return True

    def _constraints_imply(self, source, target) -> bool:
        for field, target_constraint in target.items():
            source_constraint = source.get(field)
            if source_constraint is None:
                return False
            if not self._constraint_implies(source_constraint, target_constraint):
                return False
        return True

    def _constraint_implies(self, source, target) -> bool:
        if target.equal is not None:
            return source.equal == target.equal
        if source.equal is not None:
            return self._value_satisfies(target, source.equal)

        if target.lower is not None:
            if source.lower is None:
                return False
            if source.lower < target.lower:
                return False
            if source.lower == target.lower and (target.lower_inclusive and
                                                  not source.lower_inclusive):
                return False
        if target.upper is not None:
            if source.upper is None:
                return False
            if source.upper > target.upper:
                return False
            if source.upper == target.upper and (target.upper_inclusive and
                                                  not source.upper_inclusive):
                return False
        if not target.excluded.issubset(source.excluded):
            return False
        return True

    def _conditions_equal(self, first, second) -> bool:
        if type(first) is not type(second):
            return False
        if isinstance(first, CheckIR):
            return (first.field == second.field and first.op == second.op and
                    first.value == second.value and first.ftype == second.ftype)
        if isinstance(first, (AndIR, OrIR)):
            return (self._conditions_equal(first.left, second.left) and
                    self._conditions_equal(first.right, second.right))
        if isinstance(first, NotIR):
            return self._conditions_equal(first.operand, second.operand)
        return False


def analyze_policy(policy_ir: PolicyIR) -> AnalysisReport:
    """Analyze ``policy_ir`` and return an empty report when no anomalies exist."""
    return PolicyAnalyzer(policy_ir).analyze()


__all__ = [
    'SUPPORTED_ANOMALIES', 'RuleView', 'AnalysisResult', 'AnalysisReport',
    'PolicyAnalyzer', 'analyze_policy',
]