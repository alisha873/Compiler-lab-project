# parser.py
# Recursive descent parser for NetRule.
# NetRule Language Specification v1.0
#
# Grammar implemented:
#   program      ::= policy+
#   policy       ::= POLICY IDENT '{' rule+ '}'
#   rule         ::= RULE IDENT '{' IF condition THEN action ';' '}'
#   condition    ::= or_expr
#   or_expr      ::= and_expr ( OR and_expr )*
#   and_expr     ::= not_expr ( AND not_expr )*
#   not_expr     ::= NOT not_expr | atom
#   atom         ::= '(' condition ')' | comparison
#   comparison   ::= field op value
#   field        ::= source_ip | destination_ip | source_port
#                  | destination_port | protocol
#   op           ::= == | != | < | > | <= | >=
#   value        ::= INTEGER | IP_ADDRESS | TCP | UDP | ICMP
#   action       ::= ALLOW | DENY | LOG
#
# Error recovery:
#   ParseError is raised on the first error inside a rule body.
#   The parser then synchronizes to the next RULE or POLICY keyword
#   or EOF, allowing remaining rules/policies to parse successfully.
#   Multiple errors across different rules are all reported.

from lexer import Token
from tokens import (
    KW_POLICY, KW_RULE, KW_IF, KW_THEN,
    KW_AND, KW_OR, KW_NOT,
    KW_ALLOW, KW_DENY, KW_LOG,
    KW_TCP, KW_UDP, KW_ICMP,
    KW_SRC_IP, KW_DST_IP, KW_SRC_PORT, KW_DST_PORT, KW_PROTO,
    TK_INTEGER, TK_IP_ADDRESS, TK_STRING, TK_IDENT,
    TK_EQ, TK_NEQ, TK_LT, TK_GT, TK_LTE, TK_GTE,
    TK_LBRACE, TK_RBRACE, TK_LPAREN, TK_RPAREN, TK_SEMI, TK_EOF,
    ACTIONS,
)
from ast_nodes import (
    ProgramNode, PolicyNode, RuleNode,
    ComparisonNode, BinaryLogicNode, UnaryLogicNode,
)

FIELD_TOKENS  = {KW_SRC_IP, KW_DST_IP, KW_SRC_PORT, KW_DST_PORT, KW_PROTO}
VALUE_TOKENS  = {TK_INTEGER, TK_IP_ADDRESS, KW_TCP, KW_UDP, KW_ICMP}
OP_TOKENS     = {TK_EQ, TK_NEQ, TK_LT, TK_GT, TK_LTE, TK_GTE}
OP_STRINGS    = {'EQ': '==', 'NEQ': '!=', 'LT': '<', 'GT': '>', 'LTE': '<=', 'GTE': '>='}

# Tokens that mark the start of a new rule or policy (sync points)
SYNC_TOKENS   = {KW_RULE, KW_POLICY, TK_EOF}


class ParseError(Exception):
    def __init__(self, msg, token: Token = None):
        super().__init__(msg)
        self.token = token

    def __str__(self):
        if self.token:
            return (f"Syntax error at line {self.token.line}, "
                    f"col {self.token.col}: {self.args[0]} "
                    f"(got {self.token.ttype!r} {self.token.value!r})")
        return self.args[0]


class Parser:
    def __init__(self, tokens: list):
        self.tokens = tokens
        self.pos    = 0
        self.errors : list[ParseError] = []

    # ── navigation ────────────────────────────────────────────────────────────

    def _cur(self) -> Token:
        return self.tokens[self.pos]

    def _advance(self) -> Token:
        tok = self.tokens[self.pos]
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return tok

    def _expect(self, ttype) -> Token:
        tok = self._cur()
        if tok.ttype != ttype:
            raise ParseError(f"Expected {ttype!r}", tok)
        return self._advance()

    def _match(self, *ttypes) -> bool:
        return self._cur().ttype in ttypes

    def _synchronize(self):
        """Skip tokens until a sync point is found."""
        while not self._match(*SYNC_TOKENS):
            self._advance()

    # ── program ───────────────────────────────────────────────────────────────

    def parse(self) -> ProgramNode:
        policies = []
        while not self._match(TK_EOF):
            if self._match(KW_POLICY):
                p = self._parse_policy()
                if p:
                    policies.append(p)
            else:
                tok = self._cur()
                self.errors.append(ParseError(
                    f"Expected POLICY keyword at top level", tok
                ))
                self._synchronize()
        return ProgramNode(policies)

    # ── policy ────────────────────────────────────────────────────────────────

    def _parse_policy(self) -> PolicyNode | None:
        tok = self._expect(KW_POLICY)
        try:
            name_tok = self._expect(TK_IDENT)
            self._expect(TK_LBRACE)
        except ParseError as e:
            self.errors.append(e)
            self._synchronize()
            return None

        line, col = tok.line, tok.col
        rules = []

        while not self._match(TK_RBRACE, TK_EOF):
            if self._match(KW_RULE):
                r = self._parse_rule()
                if r:
                    rules.append(r)
            else:
                t = self._cur()
                self.errors.append(ParseError(
                    f"Expected RULE inside policy {name_tok.value!r}", t
                ))
                self._synchronize()

        if self._match(TK_RBRACE):
            self._advance()
        else:
            self.errors.append(ParseError(
                f"Unclosed policy block {name_tok.value!r}", self._cur()
            ))

        if not rules:
            self.errors.append(ParseError(
                f"Policy {name_tok.value!r} contains no rules", tok
            ))

        return PolicyNode(name_tok.value, rules, line, col)

    # ── rule ──────────────────────────────────────────────────────────────────

    def _parse_rule(self) -> RuleNode | None:
        tok = self._expect(KW_RULE)
        try:
            name_tok = self._expect(TK_IDENT)
            self._expect(TK_LBRACE)
            self._expect(KW_IF)
            condition = self._parse_condition()
            self._expect(KW_THEN)
            action = self._parse_action()
            self._expect(TK_SEMI)
            self._expect(TK_RBRACE)
        except ParseError as e:
            self.errors.append(e)
            self._synchronize()
            return None

        return RuleNode(name_tok.value, condition, action, tok.line, tok.col)

    # ── action ────────────────────────────────────────────────────────────────

    def _parse_action(self) -> str:
        tok = self._cur()
        if tok.ttype not in ACTIONS:
            raise ParseError(f"Expected action (ALLOW, DENY, or LOG)", tok)
        self._advance()
        return tok.ttype   # 'ALLOW' | 'DENY' | 'LOG'

    # ── condition ─────────────────────────────────────────────────────────────

    def _parse_condition(self):
        return self._parse_or()

    def _parse_or(self):
        left = self._parse_and()
        while self._match(KW_OR):
            self._advance()
            right = self._parse_and()
            left = BinaryLogicNode('OR', left, right)
        return left

    def _parse_and(self):
        left = self._parse_not()
        while self._match(KW_AND):
            self._advance()
            right = self._parse_not()
            left = BinaryLogicNode('AND', left, right)
        return left

    def _parse_not(self):
        if self._match(KW_NOT):
            self._advance()
            operand = self._parse_not()
            return UnaryLogicNode(operand)
        return self._parse_atom()

    def _parse_atom(self):
        if self._match(TK_LPAREN):
            self._advance()
            node = self._parse_condition()
            self._expect(TK_RPAREN)
            return node
        return self._parse_comparison()

    def _parse_comparison(self) -> ComparisonNode:
        # field
        tok = self._cur()
        if tok.ttype not in FIELD_TOKENS:
            raise ParseError(
                f"Expected a network field (source_ip, destination_port, protocol, …)", tok
            )
        field_tok = self._advance()

        # operator
        op_tok = self._cur()
        if op_tok.ttype not in OP_TOKENS:
            raise ParseError(
                f"Expected a comparison operator (==, !=, <, >, <=, >=)", op_tok
            )
        op_str = OP_STRINGS[op_tok.ttype]
        self._advance()

        # value
        val_tok = self._cur()
        if val_tok.ttype not in VALUE_TOKENS:
            raise ParseError(
                f"Expected a value (integer, IP address, TCP, UDP, or ICMP)", val_tok
            )
        self._advance()

        return ComparisonNode(field_tok, op_str, val_tok, field_tok.line, field_tok.col)
