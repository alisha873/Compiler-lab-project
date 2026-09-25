"""Conservative redundancy detection for the NetRule policy IR.

A later rule is redundant when an earlier rule completely covers its matching
region and both rules have the same action.  The implication and constraint
reasoning is provided by ``policy_analyzer.py``; this module exposes the
redundancy-specific result without changing the compiler IR or executing
packets.

Only complete coverage represented by concrete ``CheckIR`` nodes is returned.
Partial overlap, different actions, and arbitrary ``OR``/``NOT`` reasoning are
intentionally excluded.
"""

from dataclasses import dataclass

from ir_nodes import CheckIR, PolicyIR, RuleIR
from policy_analyzer import AnalysisResult, analyze_policy


@dataclass(frozen=True)
class RedundancyResult:
    """A later rule fully covered by an earlier rule with the same action."""

    anomaly_type: str
    earlier_rule: RuleIR
    later_rule: RuleIR
    earlier_rule_index: int
    later_rule_index: int
    action: str
    earlier_condition: object
    later_condition: object
    relevant_conditions: tuple[CheckIR, ...]
    normalized_conditions: tuple[CheckIR, ...]
    coverage: str = 'COMPLETE'

    @property
    def earlier_rule_name(self) -> str:
        """Return the source name of the covering rule."""
        return self.earlier_rule.name

    @property
    def later_rule_name(self) -> str:
        """Return the source name of the redundant rule."""
        return self.later_rule.name

    @property
    def witness_constraints(self) -> tuple[CheckIR, ...]:
        """Return normalized checks that can guide witness construction."""
        return self.normalized_conditions


@dataclass(frozen=True)
class RedundancyReport:
    """Complete redundancy results for one policy in source order."""

    policy: PolicyIR
    redundancies: tuple[RedundancyResult, ...]

    @property
    def has_redundancies(self) -> bool:
        return bool(self.redundancies)


class RedundancyAnalyzer:
    """Detect same-action complete coverage without packet execution."""

    def __init__(self, policy_ir: PolicyIR):
        self.policy_ir = policy_ir

    def analyze(self) -> RedundancyReport:
        """Return only complete, same-action redundancy relationships.

        ``PolicyAnalyzer`` compares each later rule with earlier rules in
        source order.  Results without concrete checks are omitted because
        they would depend on unsupported Boolean reasoning.
        """
        report = analyze_policy(self.policy_ir)
        redundancies = tuple(
            self._build_result(result)
            for result in report.redundancies
            if self._has_supported_coverage(result)
        )
        return RedundancyReport(self.policy_ir, redundancies)

    def _has_supported_coverage(self, result: AnalysisResult) -> bool:
        """Return whether coverage has concrete normalized ``CheckIR`` data."""
        return bool(result.overlap_checks) and all(
            isinstance(check, CheckIR) for check in result.overlap_checks
        )

    def _build_result(self, result: AnalysisResult) -> RedundancyResult:
        """Convert a general same-action coverage result to this API."""
        relevant = tuple(result.overlap_checks)
        return RedundancyResult(
            anomaly_type='REDUNDANCY',
            earlier_rule=result.earlier_rule,
            later_rule=result.later_rule,
            earlier_rule_index=result.earlier_index,
            later_rule_index=result.later_index,
            action=result.earlier_action,
            earlier_condition=result.earlier_condition,
            later_condition=result.later_condition,
            relevant_conditions=relevant,
            normalized_conditions=relevant,
        )


def analyze_redundancy(policy_ir: PolicyIR) -> RedundancyReport:
    """Analyze ``policy_ir`` and return an empty report when none is proven."""
    return RedundancyAnalyzer(policy_ir).analyze()


__all__ = [
    'RedundancyResult', 'RedundancyReport', 'RedundancyAnalyzer',
    'analyze_redundancy',
]