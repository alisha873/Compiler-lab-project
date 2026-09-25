"""Conservative rule-shadowing detection for the NetRule policy IR.

NetRule uses first-match-wins execution.  A later rule is completely shadowed
when every packet satisfying the later rule's condition also satisfies an
earlier rule's condition.  The general, deliberately limited implication
analysis is implemented by ``policy_analyzer.py``; this module exposes the
shadowing-specific API without introducing another condition representation.

Only implication results with concrete ``CheckIR`` overlap data are returned.
Partial overlap is not complete shadowing, and arbitrary ``OR``/``NOT``
expressions are not treated as logically solved here.
"""

from dataclasses import dataclass

from ir_nodes import CheckIR, PolicyIR, RuleIR
from policy_analyzer import AnalysisResult, analyze_policy


@dataclass(frozen=True)
class ShadowingResult:
    """A complete, proven shadowing relationship between two ordered rules."""

    anomaly_type: str
    earlier_rule: RuleIR
    later_rule: RuleIR
    earlier_rule_index: int
    later_rule_index: int
    earlier_action: str
    later_action: str
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
        """Return the source name of the shadowed rule."""
        return self.later_rule.name

    @property
    def witness_constraints(self) -> tuple[CheckIR, ...]:
        """Return normalized checks that can guide witness construction."""
        return self.normalized_conditions


@dataclass(frozen=True)
class ShadowingReport:
    """Complete shadowing results for one policy in source order."""

    policy: PolicyIR
    shadowed_rules: tuple[ShadowingResult, ...]

    @property
    def shadowing(self) -> tuple[ShadowingResult, ...]:
        """Return all complete shadowing results."""
        return self.shadowed_rules

    @property
    def has_shadowing(self) -> bool:
        return bool(self.shadowed_rules)


class ShadowingAnalyzer:
    """Detect complete shadowing without executing or generating packets."""

    def __init__(self, policy_ir: PolicyIR):
        self.policy_ir = policy_ir

    def analyze(self) -> ShadowingReport:
        """Return only implication-proven complete shadowing relationships.

        ``PolicyAnalyzer`` compares each earlier rule with later rules while
        preserving their source indices.  Results without concrete checks are
        omitted because they would rely on unsupported Boolean reasoning.
        """
        report = analyze_policy(self.policy_ir)
        shadowed = tuple(
            self._build_result(result)
            for result in report.shadowing
            if self._has_supported_overlap(result)
        )
        return ShadowingReport(self.policy_ir, shadowed)

    def _has_supported_overlap(self, result: AnalysisResult) -> bool:
        """Return whether the implication has concrete ``CheckIR`` data."""
        return bool(result.overlap_checks) and all(
            isinstance(check, CheckIR) for check in result.overlap_checks
        )

    def _build_result(self, result: AnalysisResult) -> ShadowingResult:
        """Convert a general implication result to the shadowing API."""
        relevant = tuple(result.overlap_checks)
        return ShadowingResult(
            anomaly_type='SHADOWING',
            earlier_rule=result.earlier_rule,
            later_rule=result.later_rule,
            earlier_rule_index=result.earlier_index,
            later_rule_index=result.later_index,
            earlier_action=result.earlier_action,
            later_action=result.later_action,
            earlier_condition=result.earlier_condition,
            later_condition=result.later_condition,
            relevant_conditions=relevant,
            normalized_conditions=relevant,
        )


def analyze_shadowing(policy_ir: PolicyIR) -> ShadowingReport:
    """Analyze ``policy_ir`` and return an empty report when none is proven."""
    return ShadowingAnalyzer(policy_ir).analyze()


__all__ = [
    'ShadowingResult', 'ShadowingReport', 'ShadowingAnalyzer',
    'analyze_shadowing',
]