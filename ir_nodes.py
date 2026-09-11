# ir_nodes.py
# Intermediate Representation nodes for the NetRule compiler.
# NetRule Language Specification v1.0
#
# The NetRule IR is a policy-specific representation of validated rules.
# It sits between the AST (source-faithful) and the executor (runtime).
#
# IR structure:
#   PolicyIR
#   └── RuleIR (ordered list)
#       ├── conditions: flat list of CheckIR instructions
#       └── action:     'ALLOW' | 'DENY' | 'LOG'
#
# Each CheckIR corresponds to one comparison in the source condition.
# Logical structure (AND/OR/NOT) is encoded in CheckGroupIR nodes.
#
# This is deliberately simpler than the AST — the IR has eliminated
# syntactic sugar and made the evaluation model explicit.


class PolicyIR:
    """Compiled IR for one policy."""
    def __init__(self, name: str, rules: list):
        self.name  = name
        self.rules = rules   # list[RuleIR], in source order

    def __repr__(self):
        return f"PolicyIR({self.name!r}, {len(self.rules)} rules)"


class RuleIR:
    """Compiled IR for one rule."""
    def __init__(self, name: str, condition, action: str):
        self.name      = name
        self.condition = condition   # CondIR (tree)
        self.action    = action      # 'ALLOW' | 'DENY' | 'LOG'

    def __repr__(self):
        return f"RuleIR({self.name!r}, {self.action})"


# ── Condition IR nodes ────────────────────────────────────────────────────────

class CheckIR:
    """
    A single field comparison instruction.
    field : field name string (e.g. 'destination_port')
    op    : operator string   (e.g. '==')
    value : Python-typed value (int, str)
    ftype : field type string for display ('INTEGER', 'IP_ADDRESS', 'PROTOCOL')
    """
    def __init__(self, field: str, op: str, value, ftype: str):
        self.field = field
        self.op    = op
        self.value = value
        self.ftype = ftype

    def __repr__(self):
        return f"CHECK {self.field} {self.op} {self.value!r}"


class AndIR:
    """Logical AND of two condition IR nodes."""
    def __init__(self, left, right):
        self.left  = left
        self.right = right

    def __repr__(self):
        return f"AND({self.left}, {self.right})"


class OrIR:
    """Logical OR of two condition IR nodes."""
    def __init__(self, left, right):
        self.left  = left
        self.right = right

    def __repr__(self):
        return f"OR({self.left}, {self.right})"


class NotIR:
    """Logical NOT of a condition IR node."""
    def __init__(self, operand):
        self.operand = operand

    def __repr__(self):
        return f"NOT({self.operand})"
