"""Deterministic packet witnesses for supported policy-analysis results.

The analyzers expose witness constraints as the existing ``CheckIR`` objects.
This module turns those checks into the repository's existing ``Packet`` model;
it does not define a second packet type, execute packets, or generate random
test data.

Only conjunctions of supported comparisons are accepted.  An analyzer result
without concrete ``CheckIR`` constraints is rejected rather than being
approximated, which keeps unsupported ``OR``/``NOT`` reasoning conservative.
"""

from dataclasses import dataclass
from typing import Optional

from ir_nodes import CheckIR
from packet import Packet, PacketError, PROTOCOL_VALUES


_DEFAULTS = {
    'source_ip': '10.0.0.5',
    'destination_ip': '10.0.0.20',
    'protocol': 'TCP',
    'source_port': 50000,
    'destination_port': 80,
}
_FIELD_TYPES = {
    'source_ip': 'IP_ADDRESS',
    'destination_ip': 'IP_ADDRESS',
    'protocol': 'PROTOCOL',
    'source_port': 'INTEGER',
    'destination_port': 'INTEGER',
}
_PORT_FIELDS = frozenset(('source_port', 'destination_port'))
_IP_FIELDS = frozenset(('source_ip', 'destination_ip'))
_SUPPORTED_OPERATORS = frozenset(('==', '!=', '<', '>', '<=', '>='))


@dataclass(frozen=True)
class WitnessResult:
    """Outcome and explanation of one deterministic witness attempt.

    ``packet`` is a validated repository ``Packet`` and can be passed directly
    to ``Executor.execute`` when ``success`` is true.  ``packet_fields`` is a
    serializable view of the same values for display or JSON output.
    """

    success: bool
    packet: Optional[Packet]
    packet_fields: Optional[dict]
    anomaly_type: Optional[str]
    constraints: tuple[CheckIR, ...]
    satisfied_conditions: tuple[CheckIR, ...]
    error: Optional[str] = None


@dataclass
class _Constraint:
    """Constraint summary for one concrete packet field."""

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


class WitnessGenerator:
    """Generate validated packet witnesses from analyzer result objects."""

    def generate(self, anomaly) -> WitnessResult:
        """Generate a deterministic witness for a supported anomaly.

        The input is intentionally duck-typed so results from
        ``conflict_analyzer``, ``shadowing_analyzer``, or
        ``redundancy_analyzer`` can be passed directly.  It must expose
        ``anomaly_type`` and ``witness_constraints`` (or
        ``normalized_conditions``) containing ``CheckIR`` objects.
        """
        anomaly_type = getattr(anomaly, 'anomaly_type', None)
        constraints = self._get_constraints(anomaly)
        if anomaly_type not in ('CONFLICT', 'SHADOWING', 'REDUNDANCY'):
            return self._failure(
                anomaly_type, constraints,
                'Unsupported or missing anomaly type.'
            )
        if not constraints:
            return self._failure(
                anomaly_type, constraints,
                'No concrete CheckIR witness constraints were provided; '
                'the condition may require unsupported OR/NOT reasoning.'
            )

        summaries, error = self._summarize(constraints)
        if error:
            return self._failure(anomaly_type, constraints, error)

        fields = dict(_DEFAULTS)
        for field, summary in summaries.items():
            value, error = self._choose_value(field, summary)
            if error:
                return self._failure(anomaly_type, constraints, error)
            fields[field] = value

        try:
            packet = Packet.from_dict(fields)
        except (PacketError, TypeError, ValueError) as exc:
            return self._failure(
                anomaly_type, constraints,
                f'Generated fields did not form a valid Packet: {exc}'
            )

        unsatisfied = tuple(
            check for check in constraints
            if not self._satisfies(check, fields[check.field])
        )
        if unsatisfied:
            return self._failure(
                anomaly_type, constraints,
                'Generated packet does not satisfy all witness constraints.'
            )

        return WitnessResult(
            success=True,
            packet=packet,
            packet_fields=fields,
            anomaly_type=anomaly_type,
            constraints=constraints,
            satisfied_conditions=constraints,
        )

    def _get_constraints(self, anomaly) -> tuple[CheckIR, ...]:
        raw = getattr(anomaly, 'witness_constraints', None)
        if raw is None:
            raw = getattr(anomaly, 'normalized_conditions', ())
        try:
            constraints = tuple(raw)
        except TypeError:
            return ()
        return constraints

    def _summarize(self, checks: tuple[CheckIR, ...]):
        summaries = {}
        for check in checks:
            if not isinstance(check, CheckIR):
                return None, 'Witness constraints must be CheckIR objects.'
            if check.field not in _FIELD_TYPES:
                return None, f'Unsupported packet field {check.field!r}.'
            if check.ftype != _FIELD_TYPES[check.field]:
                return None, f'Field type mismatch for {check.field!r}.'
            if check.op not in _SUPPORTED_OPERATORS:
                return None, f'Unsupported comparison operator {check.op!r}.'
            summary = summaries.setdefault(
                check.field, _Constraint(check.ftype)
            )
            if not self._add_check(summary, check):
                return None, f'Contradictory constraints for {check.field!r}.'

        for field, summary in summaries.items():
            if not self._consistent(field, summary):
                return None, f'Contradictory constraints for {field!r}.'
        return summaries, None

    def _add_check(self, summary: _Constraint, check: CheckIR) -> bool:
        value = check.value
        if check.op == '==':
            if summary.equal is not None and summary.equal != value:
                return False
            summary.equal = value
        elif check.op == '!=':
            summary.excluded.add(value)
        elif check.op in ('<', '<=', '>', '>='):
            if check.ftype != 'INTEGER':
                return False
            if check.op in ('<', '<='):
                inclusive = check.op == '<='
                if (summary.upper is None or value < summary.upper or
                        (value == summary.upper and inclusive and
                         not summary.upper_inclusive)):
                    summary.upper = value
                    summary.upper_inclusive = inclusive
            else:
                inclusive = check.op == '>='
                if (summary.lower is None or value > summary.lower or
                        (value == summary.lower and inclusive and
                         not summary.lower_inclusive)):
                    summary.lower = value
                    summary.lower_inclusive = inclusive
        return True

    def _consistent(self, field: str, summary: _Constraint) -> bool:
        if summary.equal is not None:
            return self._value_satisfies(summary, summary.equal)
        if (summary.lower is not None and summary.upper is not None and
                (summary.lower > summary.upper or
                 (summary.lower == summary.upper and not
                  (summary.lower_inclusive and summary.upper_inclusive)))):
            return False
        if field in _PORT_FIELDS:
            if summary.lower is not None and summary.upper is not None:
                return self._has_integer_value(summary, 0, 65535)
            if summary.lower is not None:
                return summary.lower < 65535 or (
                    summary.lower == 65535 and summary.lower_inclusive
                )
            if summary.upper is not None:
                return summary.upper > 0 or (
                    summary.upper == 0 and summary.upper_inclusive
                )
        if field == 'protocol':
            return any(self._value_satisfies(summary, value)
                       for value in sorted(PROTOCOL_VALUES))
        return True

    def _choose_value(self, field: str, summary: _Constraint):
        if summary.equal is not None:
            value = summary.equal
            if self._value_satisfies(summary, value):
                return value, None
            return None, f'Equality constraint for {field!r} is unsatisfiable.'

        if field in _IP_FIELDS:
            candidates = (_DEFAULTS[field], '192.168.1.10', '192.168.1.11')
        elif field == 'protocol':
            candidates = tuple(sorted(PROTOCOL_VALUES))
        elif field in _PORT_FIELDS:
            candidates = self._port_candidates(summary)
        else:
            return None, f'No deterministic value strategy for {field!r}.'

        for value in candidates:
            if self._value_satisfies(summary, value):
                return value, None
        return None, f'No valid representative value exists for {field!r}.'

    def _port_candidates(self, summary: _Constraint) -> tuple[int, ...]:
        candidates = [0, 80, 443, 50000, 65535]
        if summary.lower is not None:
            lower = summary.lower + (0 if summary.lower_inclusive else 1)
            candidates.extend((lower, lower + 1))
        if summary.upper is not None:
            upper = summary.upper - (0 if summary.upper_inclusive else 1)
            candidates.extend((upper, upper - 1))
        return tuple(dict.fromkeys(
            value for value in candidates if isinstance(value, int) and
            0 <= value <= 65535
        ))

    def _has_integer_value(self, summary: _Constraint,
                           minimum: int, maximum: int) -> bool:
        return any(self._value_satisfies(summary, value)
                   for value in range(minimum, maximum + 1))

    def _value_satisfies(self, summary: _Constraint, value) -> bool:
        if value in summary.excluded:
            return False
        if summary.lower is not None:
            if value < summary.lower or (value == summary.lower and
                                         not summary.lower_inclusive):
                return False
        if summary.upper is not None:
            if value > summary.upper or (value == summary.upper and
                                         not summary.upper_inclusive):
                return False
        return True

    def _satisfies(self, check: CheckIR, value) -> bool:
        if check.op == '==':
            return value == check.value
        if check.op == '!=':
            return value != check.value
        if check.op == '<':
            return value < check.value
        if check.op == '>':
            return value > check.value
        if check.op == '<=':
            return value <= check.value
        if check.op == '>=':
            return value >= check.value
        return False

    def _failure(self, anomaly_type, constraints, error) -> WitnessResult:
        return WitnessResult(
            success=False,
            packet=None,
            packet_fields=None,
            anomaly_type=anomaly_type,
            constraints=constraints,
            satisfied_conditions=(),
            error=error,
        )


def generate_witness(anomaly) -> WitnessResult:
    """Generate a deterministic validated packet witness for ``anomaly``."""
    return WitnessGenerator().generate(anomaly)


__all__ = ['WitnessResult', 'WitnessGenerator', 'generate_witness']