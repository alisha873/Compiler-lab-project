# ast_nodes.py
# AST node definitions for the NetRule compiler.
# NetRule Language Specification v1.0
#
# Tree structure for a valid program:
#
#   ProgramNode
#   └── PolicyNode (one or more)
#       └── RuleNode (one or more)
#           ├── condition: ComparisonNode | BinaryLogicNode | UnaryLogicNode
#           └── action:   'ALLOW' | 'DENY' | 'LOG'


class ProgramNode:
    """Root of every parsed NetRule program."""
    def __init__(self, policies: list):
        self.policies = policies   # list[PolicyNode]

    def __repr__(self):
        return f"ProgramNode({len(self.policies)} policies)"


class PolicyNode:
    """A named policy block containing one or more rules."""
    def __init__(self, name: str, rules: list, line: int, col: int):
        self.name  = name          # str
        self.rules = rules         # list[RuleNode]
        self.line  = line
        self.col   = col

    def __repr__(self):
        return f"PolicyNode({self.name!r}, {len(self.rules)} rules)"


class RuleNode:
    """A named rule: IF <condition> THEN <action>."""
    def __init__(self, name: str, condition, action: str, line: int, col: int):
        self.name      = name       # str
        self.condition = condition  # ComparisonNode | BinaryLogicNode | UnaryLogicNode
        self.action    = action     # 'ALLOW' | 'DENY' | 'LOG'
        self.line      = line
        self.col       = col

    def __repr__(self):
        return f"RuleNode({self.name!r}, action={self.action})"


class ComparisonNode:
    """
    A leaf condition: <field> <op> <value>
    field_token : one of the KW_* field constants (e.g. KW_DST_PORT)
    op          : string operator ('==', '!=', '<', '>', '<=', '>=')
    value_token : the Token for the literal value (INTEGER, IP_ADDRESS, or protocol keyword)
    """
    def __init__(self, field_token, op: str, value_token, line: int, col: int):
        self.field_token = field_token   # Token
        self.op          = op            # str
        self.value_token = value_token   # Token
        self.line        = line
        self.col         = col

    def __repr__(self):
        return (f"ComparisonNode({self.field_token.value} "
                f"{self.op} {self.value_token.value})")


class BinaryLogicNode:
    """AND / OR of two sub-conditions."""
    def __init__(self, op: str, left, right):
        self.op    = op     # 'AND' | 'OR'
        self.left  = left   # condition node
        self.right = right  # condition node

    def __repr__(self):
        return f"BinaryLogicNode({self.op}, {self.left}, {self.right})"


class UnaryLogicNode:
    """NOT of a sub-condition."""
    def __init__(self, operand):
        self.op      = 'NOT'
        self.operand = operand   # condition node

    def __repr__(self):
        return f"UnaryLogicNode(NOT, {self.operand})"
