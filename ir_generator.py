# ir_generator.py
# IR generator for the NetRule compiler.
# NetRule Language Specification v1.0
#
# Converts a validated AST into the NetRule Policy IR.
# One AST PolicyNode → one PolicyIR.
# One AST RuleNode   → one RuleIR.
# Condition AST nodes → CondIR tree (CheckIR / AndIR / OrIR / NotIR).
#
# The IR generation also:
#   - Resolves literal values to Python types (str "443" → int 443)
#   - Normalises field names to lowercase strings
#   - Discards source position info (not needed at runtime)

from ast_nodes import (
    ProgramNode, PolicyNode, RuleNode,
    ComparisonNode, BinaryLogicNode, UnaryLogicNode,
)
from ir_nodes import PolicyIR, RuleIR, CheckIR, AndIR, OrIR, NotIR
from tokens import (
    KW_SRC_IP, KW_DST_IP, KW_SRC_PORT, KW_DST_PORT, KW_PROTO,
    TK_INTEGER, TK_IP_ADDRESS, KW_TCP, KW_UDP, KW_ICMP,
    FIELD_TYPES,
)

# field token type → human-readable field name
FIELD_NAMES = {
    KW_SRC_IP:   'source_ip',
    KW_DST_IP:   'destination_ip',
    KW_SRC_PORT: 'source_port',
    KW_DST_PORT: 'destination_port',
    KW_PROTO:    'protocol',
}


class IRGenerator:

    def generate_program(self, program: ProgramNode) -> dict:
        """Returns { policy_name: PolicyIR } for all policies."""
        return {
            p.name: self.generate_policy(p)
            for p in program.policies
        }

    def generate_policy(self, policy: PolicyNode) -> PolicyIR:
        rules = [self._gen_rule(r) for r in policy.rules]
        return PolicyIR(policy.name, rules)

    def _gen_rule(self, rule: RuleNode) -> RuleIR:
        cond_ir = self._gen_condition(rule.condition)
        return RuleIR(rule.name, cond_ir, rule.action)

    # ── condition lowering ────────────────────────────────────────────────────

    def _gen_condition(self, node):
        if isinstance(node, ComparisonNode):
            return self._gen_comparison(node)
        if isinstance(node, BinaryLogicNode):
            left  = self._gen_condition(node.left)
            right = self._gen_condition(node.right)
            return AndIR(left, right) if node.op == 'AND' else OrIR(left, right)
        if isinstance(node, UnaryLogicNode):
            return NotIR(self._gen_condition(node.operand))
        raise ValueError(f"Unknown AST condition node: {type(node)}")

    def _gen_comparison(self, node: ComparisonNode) -> CheckIR:
        field_name = FIELD_NAMES[node.field_token.ttype]
        ftype      = FIELD_TYPES[node.field_token.ttype][0]
        value      = self._resolve_value(node.value_token, ftype)
        return CheckIR(field_name, node.op, value, ftype)

    def _resolve_value(self, tok, ftype: str):
        """Convert a value token to its Python runtime type."""
        if ftype == 'INTEGER':
            return int(tok.value)
        if ftype == 'IP_ADDRESS':
            return tok.value          # keep as string '192.168.1.10'
        if ftype == 'PROTOCOL':
            return tok.value          # 'TCP' | 'UDP' | 'ICMP'
        return tok.value

    # ── display ───────────────────────────────────────────────────────────────

    def display_policy(self, policy_ir: PolicyIR, indent=0):
        pad = '  ' * indent
        print(f"{pad}PolicyIR: {policy_ir.name!r}")
        for rule in policy_ir.rules:
            print(f"{pad}  RuleIR: {rule.name!r}  →  {rule.action}")
            self._display_cond(rule.condition, indent + 2)

    def _display_cond(self, node, indent: int):
        pad = '  ' * indent
        if isinstance(node, CheckIR):
            print(f"{pad}CHECK  {node.field} {node.op} {node.value!r}")
        elif isinstance(node, AndIR):
            print(f"{pad}AND")
            self._display_cond(node.left,  indent + 1)
            self._display_cond(node.right, indent + 1)
        elif isinstance(node, OrIR):
            print(f"{pad}OR")
            self._display_cond(node.left,  indent + 1)
            self._display_cond(node.right, indent + 1)
        elif isinstance(node, NotIR):
            print(f"{pad}NOT")
            self._display_cond(node.operand, indent + 1)
