# tokens.py
# All token type constants for the NetRule compiler.
# NetRule Language Specification v1.0

# ── Keywords ──────────────────────────────────────────────────────────────────
KW_POLICY   = 'POLICY'
KW_RULE     = 'RULE'
KW_IF       = 'IF'
KW_THEN     = 'THEN'
KW_AND      = 'AND'
KW_OR       = 'OR'
KW_NOT      = 'NOT'
KW_ALLOW    = 'ALLOW'
KW_DENY     = 'DENY'
KW_LOG      = 'LOG'

# ── Protocol value keywords ───────────────────────────────────────────────────
KW_TCP      = 'TCP'
KW_UDP      = 'UDP'
KW_ICMP     = 'ICMP'

# ── Built-in network field identifiers ───────────────────────────────────────
KW_SRC_IP   = 'source_ip'
KW_DST_IP   = 'destination_ip'
KW_SRC_PORT = 'source_port'
KW_DST_PORT = 'destination_port'
KW_PROTO    = 'protocol'

# ── Literals ─────────────────────────────────────────────────────────────────
TK_INTEGER      = 'INTEGER'
TK_IP_ADDRESS   = 'IP_ADDRESS'

# ── Identifiers ───────────────────────────────────────────────────────────────
TK_IDENT        = 'IDENT'

# ── Operators ────────────────────────────────────────────────────────────────
TK_EQ   = 'EQ'
TK_NEQ  = 'NEQ'
TK_LT   = 'LT'
TK_GT   = 'GT'
TK_LTE  = 'LTE'
TK_GTE  = 'GTE'

# ── Punctuation ───────────────────────────────────────────────────────────────
TK_LBRACE   = 'LBRACE'
TK_RBRACE   = 'RBRACE'
TK_LPAREN   = 'LPAREN'
TK_RPAREN   = 'RPAREN'
TK_SEMI     = 'SEMI'

# ── Special ───────────────────────────────────────────────────────────────────
TK_EOF      = 'EOF'

# ── Lookup tables ─────────────────────────────────────────────────────────────
KEYWORDS = {
    'POLICY': KW_POLICY, 'RULE': KW_RULE,
    'IF': KW_IF,         'THEN': KW_THEN,
    'AND': KW_AND,       'OR': KW_OR,    'NOT': KW_NOT,
    'ALLOW': KW_ALLOW,   'DENY': KW_DENY,'LOG': KW_LOG,
    'TCP': KW_TCP,       'UDP': KW_UDP,  'ICMP': KW_ICMP,
}

BUILTIN_FIELDS = {
    'source_ip':        KW_SRC_IP,
    'destination_ip':   KW_DST_IP,
    'source_port':      KW_SRC_PORT,
    'destination_port': KW_DST_PORT,
    'protocol':         KW_PROTO,
}

# field_token -> (type_name, allowed_operator_strings)
FIELD_TYPES = {
    KW_SRC_IP:   ('IP_ADDRESS', {'==', '!='}),
    KW_DST_IP:   ('IP_ADDRESS', {'==', '!='}),
    KW_SRC_PORT: ('INTEGER',    {'==', '!=', '<', '>', '<=', '>='}),
    KW_DST_PORT: ('INTEGER',    {'==', '!=', '<', '>', '<=', '>='}),
    KW_PROTO:    ('PROTOCOL',   {'==', '!='}),
}

# For each field type, which token types are valid comparison values
VALID_VALUE_TYPES = {
    'IP_ADDRESS': {TK_IP_ADDRESS},
    'INTEGER':    {TK_INTEGER},
    'PROTOCOL':   {KW_TCP, KW_UDP, KW_ICMP},
}

ACTIONS = {KW_ALLOW, KW_DENY, KW_LOG}
