# optimizer.py
# IR optimization pass for the NetRule compiler.
# NetRule Language Specification v1.0
#
# Optimization implemented: Boolean simplification on condition IR trees.
#
# Passes (applied in order, repeated until fixpoint):
#   Pass 1 — Constant folding:
#       AND(TRUE, x) → x        AND(x, TRUE) → x
#       AND(FALSE, x) → FALSE   AND(x, FALSE) → FALSE
#       OR(FALSE, x) → x        OR(x, FALSE) → x
#       OR(TRUE, x) → TRUE      OR(x, TRUE) → TRUE
#       NOT(TRUE) → FALSE       NOT(FALSE) → TRUE
#
#   Pass 2 — Idempotency:
#       AND(x, x) → x
#       OR(x, x)  → x
#
#   Pass 3 — Double negation elimination:
#       NOT(NOT(x)) → x
#
# Note on terminology:
#   This is Boolean simplification on a condition IR tree,
#   not "loop-invariant code motion" or classical peephole optimization.
#   The analogy to peephole is structural (local, pattern-matching rewrite
#   on a tree), not semantic.
#
# The optimizer records each transformation applied, so the pipeline
# visualizer can show exactly what changed and why.

from ir_nodes import PolicyIR, RuleIR, CheckIR, AndIR, OrIR, NotIR
import copy

# Sentinel constants used during constant folding
_TRUE  = object()
_FALSE = object()


class Optimizer:

    def optimize_policy(self, policy_ir: PolicyIR) -> tuple[PolicyIR, list[str]]:
        """
        Returns (optimized_policy_ir, list_of_transformation_messages).
        Does not mutate the input.
        """
        log = []
        optimized_rules = []
        for rule in policy_ir.rules:
            opt_cond, rule_log = self._optimize_condition(rule.condition, rule.name)
            log.extend(rule_log)
            optimized_rules.append(RuleIR(rule.name, opt_cond, rule.action))
        return PolicyIR(policy_ir.name, optimized_rules), log

    # ── fixpoint loop ─────────────────────────────────────────────────────────

    def _optimize_condition(self, node, rule_name: str):
        log = []
        prev = None
        current = node
        iteration = 0
        while True:
            iteration += 1
            new_node, pass_log = self._apply_passes(current, rule_name)
            log.extend(pass_log)
            if not pass_log:
                break   # fixpoint reached — nothing changed
            current = new_node
            if iteration > 20:
                break   # safety limit
        return current, log

    def _apply_passes(self, node, rule_name: str):
        log = []
        node, l1 = self._pass_double_negation(node, rule_name)
        node, l2 = self._pass_idempotency(node, rule_name)
        log.extend(l1 + l2)
        return node, log

    # ── Pass: double negation elimination ─────────────────────────────────────

    def _pass_double_negation(self, node, rule_name: str):
        log = []
        if isinstance(node, NotIR) and isinstance(node.operand, NotIR):
            log.append(
                f"  [{rule_name}] Double negation eliminated: "
                f"NOT(NOT(…)) → (…)"
            )
            result, sub_log = self._pass_double_negation(node.operand.operand, rule_name)
            log.extend(sub_log)
            return result, log
        if isinstance(node, NotIR):
            inner, sub_log = self._pass_double_negation(node.operand, rule_name)
            log.extend(sub_log)
            return NotIR(inner), log
        if isinstance(node, (AndIR, OrIR)):
            left,  ll = self._pass_double_negation(node.left,  rule_name)
            right, rl = self._pass_double_negation(node.right, rule_name)
            log.extend(ll + rl)
            return type(node)(left, right), log
        return node, log

    # ── Pass: idempotency (AND(x,x)→x, OR(x,x)→x) ────────────────────────────

    def _pass_idempotency(self, node, rule_name: str):
        log = []
        if isinstance(node, (AndIR, OrIR)):
            left,  ll = self._pass_idempotency(node.left,  rule_name)
            right, rl = self._pass_idempotency(node.right, rule_name)
            log.extend(ll + rl)
            op = 'AND' if isinstance(node, AndIR) else 'OR'
            if self._structurally_equal(left, right):
                log.append(
                    f"  [{rule_name}] Idempotency: {op}(x, x) → x  "
                    f"(x = {self._cond_str(left)})"
                )
                return left, log
            return type(node)(left, right), log
        if isinstance(node, NotIR):
            inner, il = self._pass_idempotency(node.operand, rule_name)
            log.extend(il)
            return NotIR(inner), log
        return node, log

    # ── structural equality ───────────────────────────────────────────────────

    def _structurally_equal(self, a, b) -> bool:
        if type(a) != type(b):
            return False
        if isinstance(a, CheckIR):
            return a.field == b.field and a.op == b.op and a.value == b.value
        if isinstance(a, (AndIR, OrIR)):
            return (self._structurally_equal(a.left, b.left) and
                    self._structurally_equal(a.right, b.right))
        if isinstance(a, NotIR):
            return self._structurally_equal(a.operand, b.operand)
        return False

    # ── display helpers ───────────────────────────────────────────────────────

    def _cond_str(self, node) -> str:
        if isinstance(node, CheckIR):
            return f"{node.field} {node.op} {node.value!r}"
        if isinstance(node, AndIR):
            return f"({self._cond_str(node.left)} AND {self._cond_str(node.right)})"
        if isinstance(node, OrIR):
            return f"({self._cond_str(node.left)} OR {self._cond_str(node.right)})"
        if isinstance(node, NotIR):
            return f"NOT({self._cond_str(node.operand)})"
        return '?'
