# semantic_analyzer.py
# Semantic analysis for the NetRule compiler.
# NetRule Language Specification v1.0
#
# Checks performed (in order):
#   1. Policy name uniqueness
#   2. Rule name uniqueness within a policy
#   3. Field existence (all fields are built-in; no user-defined fields)
#   4. Operator validity for field type
#   5. Value type compatibility with field type
#   6. Action validity
#   7. Unreachable rule analysis (static analysis under first-match-wins)
#
# Unreachable rule analysis (Rule 6 from spec):
#   For each pair (Ri, Rj) where i < j in the same policy:
#   If every packet satisfying Rj's condition also satisfies Ri's condition,
#   then Rj is unreachable.
#
#   v1.0 implements a sound, deliberately limited version:
#   A rule Ri makes Rj unreachable if Ri's condition is a CONJUNCT-SUBSET
#   of Rj's condition — meaning every top-level AND clause in Ri also
#   appears (structurally) in Rj. This catches the most common case:
#       RULE r1: IF protocol == TCP THEN DENY
#       RULE r2: IF protocol == TCP AND destination_port == 443 THEN ALLOW
#   r2 is unreachable because r1 matches all TCP traffic.
#
#   We do NOT claim full logical equivalence (that would require a SAT solver).
#   The analysis is sound: it only reports unreachability when it can prove it.

from ast_nodes import (
    ProgramNode, PolicyNode, RuleNode,
    ComparisonNode, BinaryLogicNode, UnaryLogicNode,
)
from symbol_table import SymbolTable


class SemanticError(Exception):
    def __init__(self, msg, line=None, col=None):
        super().__init__(msg)
        self.line = line
        self.col  = col

    def __str__(self):
        loc = f" at line {self.line}, col {self.col}" if self.line else ""
        return f"Semantic error{loc}: {self.args[0]}"


class SemanticWarning:
    def __init__(self, msg, line=None, col=None):
        self.msg  = msg
        self.line = line
        self.col  = col

    def __str__(self):
        loc = f" at line {self.line}, col {self.col}" if self.line else ""
        return f"Warning{loc}: {self.msg}"


class SemanticAnalyzer:
    def __init__(self, symbol_table: SymbolTable):
        self.st       = symbol_table
        self.errors   : list[SemanticError]   = []
        self.warnings : list[SemanticWarning] = []

    def _err(self, msg, line=None, col=None):
        self.errors.append(SemanticError(msg, line, col))

    def _warn(self, msg, line=None, col=None):
        self.warnings.append(SemanticWarning(msg, line, col))

    # ── entry point ───────────────────────────────────────────────────────────

    def analyze(self, program: ProgramNode) -> bool:
        """Returns True if no errors (warnings are non-fatal)."""
        for policy in program.policies:
            self._check_policy(policy)
        return len(self.errors) == 0

    # ── policy ────────────────────────────────────────────────────────────────

    def _check_policy(self, policy: PolicyNode):
        if not self.st.register_policy(policy.name):
            self._err(
                f"Duplicate policy name {policy.name!r}",
                policy.line, policy.col
            )

        for rule in policy.rules:
            self._check_rule(rule, policy.name)

        # Unreachable rule analysis across rules in this policy
        self._check_reachability(policy)

    # ── rule ──────────────────────────────────────────────────────────────────

    def _check_rule(self, rule: RuleNode, policy_name: str):
        if not self.st.register_rule(policy_name, rule.name):
            self._err(
                f"Duplicate rule name {rule.name!r} in policy {policy_name!r}",
                rule.line, rule.col
            )
        self._check_condition(rule.condition)
        if not self.st.action_valid(rule.action):
            self._err(
                f"Invalid action {rule.action!r}; must be ALLOW, DENY, or LOG",
                rule.line, rule.col
            )

    # ── condition ─────────────────────────────────────────────────────────────

    def _check_condition(self, node):
        if isinstance(node, ComparisonNode):
            self._check_comparison(node)
        elif isinstance(node, BinaryLogicNode):
            self._check_condition(node.left)
            self._check_condition(node.right)
        elif isinstance(node, UnaryLogicNode):
            self._check_condition(node.operand)

    def _check_comparison(self, node: ComparisonNode):
        field_type = node.field_token.ttype
        op         = node.op
        val_type   = node.value_token.ttype

        # 1. Field must exist (parser guarantees this, but belt-and-suspenders)
        if not self.st.field_exists(field_type):
            self._err(
                f"Unknown network field {node.field_token.value!r}",
                node.line, node.col
            )
            return

        # 2. Operator must be valid for this field
        allowed = self.st.allowed_ops(field_type)
        if op not in allowed:
            ftype_name = self.st.field_type(field_type)
            self._err(
                f"Operator {op!r} is not valid for field "
                f"{node.field_token.value!r} (type {ftype_name}). "
                f"Allowed: {sorted(allowed)}",
                node.line, node.col
            )

        # 3. Value type must be compatible with field type
        if not self.st.value_compatible(field_type, val_type):
            ftype_name = self.st.field_type(field_type)
            self._err(
                f"Type mismatch: field {node.field_token.value!r} has type "
                f"{ftype_name}, but value {node.value_token.value!r} has type "
                f"{val_type}. These are incompatible.",
                node.line, node.col
            )

    # ── unreachable rule analysis ─────────────────────────────────────────────

    def _check_reachability(self, policy: PolicyNode):
        """
        For each rule Rj, check if any earlier rule Ri makes it unreachable.
        Uses conjunct-subset analysis: Ri makes Rj unreachable if every
        top-level conjunct of Ri's condition also appears in Rj's condition.
        """
        for j, rj in enumerate(policy.rules):
            for i in range(j):
                ri = policy.rules[i]
                if self._ri_covers_rj(ri.condition, rj.condition):
                    self._warn(
                        f"Rule {rj.name!r} is unreachable in policy {policy.name!r}. "
                        f"Earlier rule {ri.name!r} matches every packet that "
                        f"{rj.name!r} would match (first-match-wins semantics).",
                        rj.line, rj.col
                    )
                    break  # one warning per rule is enough

    def _ri_covers_rj(self, ci, cj) -> bool:
        """
        Returns True if condition ci is a conjunct-subset of cj.
        Meaning: every top-level AND clause in ci also appears in cj.
        This is a sound, limited check — false negatives are acceptable.
        """
        ri_conjuncts = self._top_conjuncts(ci)
        rj_conjuncts = self._top_conjuncts(cj)

        for rc in ri_conjuncts:
            # rc must appear somewhere in rj's conjuncts
            if not any(self._conditions_equal(rc, jc) for jc in rj_conjuncts):
                return False
        return True

    def _top_conjuncts(self, node) -> list:
        """Flatten top-level AND nodes into a list of leaf conditions."""
        if isinstance(node, BinaryLogicNode) and node.op == 'AND':
            return self._top_conjuncts(node.left) + self._top_conjuncts(node.right)
        return [node]

    def _conditions_equal(self, a, b) -> bool:
        """Structural equality of two condition nodes (for conjunct matching)."""
        if type(a) != type(b):
            return False
        if isinstance(a, ComparisonNode):
            return (a.field_token.ttype == b.field_token.ttype and
                    a.op == b.op and
                    a.value_token.value == b.value_token.value)
        if isinstance(a, BinaryLogicNode):
            return (a.op == b.op and
                    self._conditions_equal(a.left, b.left) and
                    self._conditions_equal(a.right, b.right))
        if isinstance(a, UnaryLogicNode):
            return self._conditions_equal(a.operand, b.operand)
        return False

    # ── display ───────────────────────────────────────────────────────────────

    def display_results(self):
        if self.errors:
            print(f"\n  ❌ Semantic errors ({len(self.errors)}):")
            for e in self.errors:
                print(f"    {e}")
        if self.warnings:
            print(f"\n  ⚠  Semantic warnings ({len(self.warnings)}):")
            for w in self.warnings:
                print(f"    {w}")
        if not self.errors and not self.warnings:
            print("\n  ✅ Semantic analysis passed — no errors, no warnings.")
        elif not self.errors:
            print(f"\n  ✅ Semantic analysis passed ({len(self.warnings)} warning(s)).")
