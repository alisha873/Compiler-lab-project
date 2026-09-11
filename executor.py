# executor.py
# Policy execution engine for the NetRule compiler.
# NetRule Language Specification v1.0
#
# Execution model:
#   - Rules are evaluated in source order (first-match-wins).
#   - The first rule whose condition evaluates to True determines the action.
#   - If no rule matches, the default action is DENY (deny-by-default).
#   - LOG means: permit the packet AND log to stdout.
#
# The executor walks the PolicyIR (not the AST directly).
# This is the "runtime stage" of the compiler pipeline.
# It interprets the IR — it does not generate machine code.

from ir_nodes import PolicyIR, RuleIR, CheckIR, AndIR, OrIR, NotIR
from packet import Packet


class ExecutionResult:
    def __init__(self, decision: str, matched_rule: str | None,
                 trace: list[str]):
        self.decision     = decision       # 'ALLOW' | 'DENY' | 'LOG'
        self.matched_rule = matched_rule   # rule name or None (default deny)
        self.trace        = trace          # step-by-step evaluation log

    def display(self):
        print(f"\n  {'Matched rule':<22} {self.matched_rule or '(none — default DENY)'}")
        print(f"  {'Decision':<22} {self.decision}")
        if self.trace:
            print("\n  Evaluation trace:")
            for line in self.trace:
                print(f"    {line}")


class Executor:

    def execute(self, policy_ir: PolicyIR, packet: Packet) -> ExecutionResult:
        """
        Evaluate packet against policy under first-match-wins semantics.
        Returns an ExecutionResult.
        """
        trace = []
        for rule in policy_ir.rules:
            trace.append(f"Evaluating rule {rule.name!r}:")
            result, rule_trace = self._eval_condition(rule.condition, packet)
            trace.extend(f"  {l}" for l in rule_trace)
            if result:
                trace.append(f"  → MATCHED → {rule.action}")
                return ExecutionResult(rule.action, rule.name, trace)
            else:
                trace.append(f"  → no match")

        trace.append("No rule matched — applying default DENY.")
        return ExecutionResult('DENY', None, trace)

    # ── condition evaluation ──────────────────────────────────────────────────

    def _eval_condition(self, node, packet: Packet) -> tuple[bool, list[str]]:
        """Returns (bool_result, trace_lines)."""
        if isinstance(node, CheckIR):
            return self._eval_check(node, packet)
        if isinstance(node, AndIR):
            lval, lt = self._eval_condition(node.left,  packet)
            rval, rt = self._eval_condition(node.right, packet)
            result = lval and rval
            trace = lt + rt + [
                f"AND({lval}, {rval}) → {result}"
            ]
            return result, trace
        if isinstance(node, OrIR):
            lval, lt = self._eval_condition(node.left,  packet)
            rval, rt = self._eval_condition(node.right, packet)
            result = lval or rval
            trace = lt + rt + [f"OR({lval}, {rval}) → {result}"]
            return result, trace
        if isinstance(node, NotIR):
            val, t = self._eval_condition(node.operand, packet)
            result = not val
            return result, t + [f"NOT({val}) → {result}"]
        raise ValueError(f"Unknown IR condition node: {type(node)}")

    def _eval_check(self, check: CheckIR, packet: Packet) -> tuple[bool, list[str]]:
        pkt_val = packet.get(check.field)
        rule_val = check.value

        result = self._compare(pkt_val, check.op, rule_val, check.ftype)
        trace  = [
            f"CHECK {check.field} {check.op} {rule_val!r}  "
            f"[packet={pkt_val!r}]  → {result}"
        ]
        return result, trace

    def _compare(self, pkt_val, op: str, rule_val, ftype: str) -> bool:
        if pkt_val is None:
            return False
        try:
            if op == '==': return pkt_val == rule_val
            if op == '!=': return pkt_val != rule_val
            if op == '<':  return pkt_val <  rule_val
            if op == '>':  return pkt_val >  rule_val
            if op == '<=': return pkt_val <= rule_val
            if op == '>=': return pkt_val >= rule_val
        except TypeError as e:
            raise RuntimeError(
                f"Runtime type error comparing packet field {pkt_val!r} "
                f"{op} {rule_val!r}: {e}. "
                f"This should have been caught by semantic analysis."
            )
        return False
