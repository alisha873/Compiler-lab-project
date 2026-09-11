# symbol_table.py
# Symbol table for the NetRule compiler.
# NetRule Language Specification v1.0
#
# The symbol table is STATIC — it is not loaded from external files.
# NetRule has no user-defined variables or types.
# The table encodes the fixed network field schema and the valid action set.
#
# Distinction from SemanticAnalyzer scope:
#   SymbolTable      = global, program-independent schema for field types
#   SemanticAnalyzer = walks the AST and uses the symbol table to validate
#                      each individual rule and policy
#
# Used by the semantic analyzer to answer:
#   "What type does this field have?"
#   "What operators are valid for this field?"
#   "Is this value type compatible with this field?"
#   "Is this a valid action?"

from tokens import (
    KW_SRC_IP, KW_DST_IP, KW_SRC_PORT, KW_DST_PORT, KW_PROTO,
    KW_TCP, KW_UDP, KW_ICMP,
    TK_INTEGER, TK_IP_ADDRESS,
    FIELD_TYPES, VALID_VALUE_TYPES, ACTIONS,
)


class SymbolTable:
    """
    Fixed schema registry for NetRule's built-in network fields.

    Schema:
        field_token  →  (type_name, allowed_ops)

    Where type_name ∈ { 'IP_ADDRESS', 'INTEGER', 'PROTOCOL' }
    and allowed_ops is a set of operator strings.
    """

    def __init__(self):
        # Immutable field schema — defined by the language spec, not the user
        self._fields = dict(FIELD_TYPES)
        self._actions = set(ACTIONS)

        # Policy/rule registry — populated during semantic analysis
        # { policy_name → set(rule_names) }
        self._policy_registry: dict[str, set] = {}

    # ── field lookup ──────────────────────────────────────────────────────────

    def field_exists(self, field_token_type: str) -> bool:
        return field_token_type in self._fields

    def field_type(self, field_token_type: str) -> str:
        """Return the MiniType of a field. Raises KeyError if not found."""
        return self._fields[field_token_type][0]

    def allowed_ops(self, field_token_type: str) -> set:
        """Return the set of valid operator strings for a field."""
        return self._fields[field_token_type][1]

    def value_compatible(self, field_token_type: str, value_token_type: str) -> bool:
        """
        Check whether a value token type is compatible with a field's type.
        e.g. destination_port (INTEGER) compatible with TK_INTEGER → True
             destination_port (INTEGER) compatible with KW_TCP     → False
             protocol (PROTOCOL) compatible with KW_TCP            → True
        """
        ftype = self.field_type(field_token_type)
        valid = VALID_VALUE_TYPES.get(ftype, set())
        return value_token_type in valid

    # ── policy/rule registry ──────────────────────────────────────────────────

    def register_policy(self, name: str) -> bool:
        """Register a policy name. Returns False if already registered (duplicate)."""
        if name in self._policy_registry:
            return False
        self._policy_registry[name] = set()
        return True

    def register_rule(self, policy_name: str, rule_name: str) -> bool:
        """Register a rule under a policy. Returns False if rule name is duplicate."""
        if policy_name not in self._policy_registry:
            self._policy_registry[policy_name] = set()
        rules = self._policy_registry[policy_name]
        if rule_name in rules:
            return False
        rules.add(rule_name)
        return True

    def policy_exists(self, name: str) -> bool:
        return name in self._policy_registry

    # ── action lookup ─────────────────────────────────────────────────────────

    def action_valid(self, action: str) -> bool:
        return action in self._actions

    # ── display ───────────────────────────────────────────────────────────────

    def display(self):
        print("\n╔══════════════════════════════════════════════════╗")
        print("║                  SYMBOL TABLE                   ║")
        print("╠══════════════════════════════════════════════════╣")
        print("║  BUILT-IN NETWORK FIELDS                        ║")
        print("║  ─────────────────────────────────────────────  ║")
        for field, (ftype, ops) in self._fields.items():
            ops_str = ', '.join(sorted(ops))
            print(f"║  {field:<20}  {ftype:<12}  [{ops_str}]")
        print("║                                                  ║")
        print("║  VALID ACTIONS:  ALLOW  DENY  LOG               ║")
        if self._policy_registry:
            print("╠══════════════════════════════════════════════════╣")
            print("║  REGISTERED POLICIES                            ║")
            for pname, rules in self._policy_registry.items():
                print(f"║  POLICY {pname!r:<20}  ({len(rules)} rules)")
                for r in sorted(rules):
                    print(f"║    ├─ {r}")
        print("╚══════════════════════════════════════════════════╝")
