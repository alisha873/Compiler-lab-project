"""Conservative conflict detection for the NetRule policy IR.

The general relationship analysis lives in ``policy_analyzer.py``.  This
module provides the conflict-specific API used by later stages.  It consumes
the existing ``PolicyIR`` and reuses ``AnalysisResult`` data rather than
introducing another condition representation or executing packets.

Only overlaps represented by a non-empty sequence of existing ``CheckIR``
nodes are returned.  This supports conjunctions of comparisons while
intentionally declining to infer arbitrary ``OR``/``NOT`` satisfiability.
"""

from dataclasses import dataclass

from ir_nodes import CheckIR, PolicyIR
from policy_analyzer import AnalysisResult, analyze_policy


@dataclass(frozen=True)
class ConflictResult:
    """A supported conflict between an earlier and later rule.

    ``overlapping_conditions`` and ``normalized_conditions`` contain the
    actual normalized ``CheckIR`` objects used to establish the overlap.  The
    latter name makes the data contract explicit for ``witness_generator``;
    neither field introduces a second IR.
    """

    anomaly_type: str
    earlier_rule_name: str
    earlier_rule_index: int
    later_rule_name: str
    later_rule_index: int
    earlier_action: str
    later_action: str
    earlier_condition: object
    later_condition: object
    overlapping_conditions: tuple[CheckIR, ...]
    normalized_conditions: tuple[CheckIR, ...]

    @property
    def witness_constraints(self) -> tuple[CheckIR, ...]:
        """Return normalized checks suitable for witness construction."""
        return self.normalized_conditions


@dataclass(frozen=True)
class ConflictReport:
    """Conflict results for one policy, in original rule-pair order."""

    policy: PolicyIR
    conflicts: tuple[ConflictResult, ...]

    @property
    def has_conflicts(self) -> bool:
        return bool(self.conflicts)


class ConflictAnalyzer:
    """Detect supported conflicts without executing or generating packets."""

    def __init__(self, policy_ir: PolicyIR):
        self.policy_ir = policy_ir

    def analyze(self) -> ConflictReport:
        """Return all conservatively established action conflicts.

        ``PolicyAnalyzer`` performs the pairwise comparison in source order.
        Results without concrete ``CheckIR`` overlap data are omitted because
        they may depend on Boolean reasoning outside this module's scope.
        """
        report = analyze_policy(self.policy_ir)
        conflicts = tuple(
            self._build_result(result)
            for result in report.conflicts
            if self._has_supported_overlap(result)
        )
        return ConflictReport(self.policy_ir, conflicts)

    def _has_supported_overlap(self, result: AnalysisResult) -> bool:
        """Return whether a policy result has usable conjunction checks."""
        return bool(result.overlap_checks) and all(
            isinstance(check, CheckIR) for check in result.overlap_checks
        )

    def _build_result(self, result: AnalysisResult) -> ConflictResult:
        """Convert a general analysis result to the conflict API."""
        overlapping = tuple(result.overlap_checks)
        return ConflictResult(
            anomaly_type='CONFLICT',
            earlier_rule_name=result.earlier_rule.name,
            earlier_rule_index=result.earlier_index,
            later_rule_name=result.later_rule.name,
            later_rule_index=result.later_index,
            earlier_action=result.earlier_action,
            later_action=result.later_action,
            earlier_condition=result.earlier_condition,
            later_condition=result.later_condition,
            overlapping_conditions=overlapping,
            normalized_conditions=overlapping,
        )


def analyze_conflicts(policy_ir: PolicyIR) -> ConflictReport:
    """Analyze ``policy_ir`` and return an empty report when none are found."""
    return ConflictAnalyzer(policy_ir).analyze()


__all__ = [
    'ConflictResult', 'ConflictReport', 'ConflictAnalyzer',
    'analyze_conflicts',
]