# lexer.py
# Hand-written state-machine scanner for NetRule.
# NetRule Language Specification v1.0
#
# Token rules:
#   KEYWORDS     — matched case-sensitively (POLICY, RULE, IF, AND, … TCP, UDP, ICMP)
#   FIELDS       — matched only by their exact canonical spelling (source_ip, destination_port, …)
#   IDENT        — [a-zA-Z_][a-zA-Z0-9_]* that is not a keyword/field
#   INTEGER      — one or more digits, no leading dot, no trailing dot
#   IP_ADDRESS   — four decimal octets separated by dots (0-255 each)
#                  Lexed greedily: "192.168.1.10" is one IP_ADDRESS token,
#                  not INTEGER DOT INTEGER DOT …
#   OPERATORS    — ==, !=, <, >, <=, >=
#   PUNCTUATION  — { } ( ) ;
#   COMMENTS     — # to end of line, silently discarded
#   WHITESPACE   — spaces, tabs, newlines, silently discarded
#
# Error handling:
#   Unexpected characters are recorded as LexerError objects (with line/col).
#   The scanner skips the bad character and continues (error recovery).
#   The caller receives (token_list, error_list) and decides whether to abort.

from tokens import (
    KEYWORDS, BUILTIN_FIELDS,
    TK_INTEGER, TK_IP_ADDRESS, TK_IDENT,
    TK_EQ, TK_NEQ, TK_LT, TK_GT, TK_LTE, TK_GTE,
    TK_LBRACE, TK_RBRACE, TK_LPAREN, TK_RPAREN, TK_SEMI, TK_EOF,
)


class Token:
    __slots__ = ('ttype', 'value', 'line', 'col')

    def __init__(self, ttype, value, line, col):
        self.ttype = ttype
        self.value = value
        self.line  = line   # 1-based
        self.col   = col    # 1-based

    def __repr__(self):
        return f"Token({self.ttype}, {self.value!r}, {self.line}:{self.col})"


class LexerError(Exception):
    def __init__(self, msg, line, col):
        super().__init__(msg)
        self.line = line
        self.col  = col

    def __str__(self):
        return f"Lexical error at line {self.line}, col {self.col}: {self.args[0]}"


class Lexer:
    def __init__(self, source: str):
        self.source = source
        self.pos    = 0
        self.line   = 1
        self.col    = 1
        self.tokens : list[Token]      = []
        self.errors : list[LexerError] = []

    # ── navigation ────────────────────────────────────────────────────────────

    def _cur(self):
        return self.source[self.pos] if self.pos < len(self.source) else None

    def _peek(self, n=1):
        i = self.pos + n
        return self.source[i] if i < len(self.source) else None

    def _advance(self):
        ch = self.source[self.pos]
        self.pos += 1
        if ch == '\n':
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def _here(self):
        return self.line, self.col

    def _err(self, msg, line=None, col=None):
        self.errors.append(LexerError(msg, line or self.line, col or self.col))

    # ── readers ───────────────────────────────────────────────────────────────

    def _read_word(self):
        """Read [a-zA-Z_][a-zA-Z0-9_]* and classify as keyword / field / ident."""
        line, col = self._here()
        start = self.pos
        while self._cur() and (self._cur().isalnum() or self._cur() == '_'):
            self._advance()
        word = self.source[start:self.pos]

        # 1. Exact-case keyword match (POLICY, IF, TCP …)
        if word in KEYWORDS:
            return Token(KEYWORDS[word], word, line, col)

        # 2. Exact-case built-in field match only (source_ip, destination_port, protocol…)
        if word in BUILTIN_FIELDS:
            return Token(BUILTIN_FIELDS[word], word, line, col)

        # 3. Generic identifier (policy/rule names)
        return Token(TK_IDENT, word, line, col)

    def _try_read_ip(self, first_digits: str, start_line: int, start_col: int):
        """
        After reading a run of digits, check if this is an IP address
        (digits.digits.digits.digits).  Returns a Token for a valid IP,
        None if it is not an IP candidate, or False if it is an invalid IPv4
        literal that was already diagnosed as a lexical error.
        """
        saved_pos  = self.pos
        saved_line = self.line
        saved_col  = self.col

        parts = [first_digits]
        for _ in range(3):
            if self._cur() != '.':
                # not enough dots — not an IP
                self.pos  = saved_pos
                self.line = saved_line
                self.col  = saved_col
                return None
            self._advance()  # consume '.'
            start = self.pos
            if not (self._cur() and self._cur().isdigit()):
                self.pos  = saved_pos
                self.line = saved_line
                self.col  = saved_col
                return None
            while self._cur() and self._cur().isdigit():
                self._advance()
            parts.append(self.source[start:self.pos])

        # Validate octets 0-255
        ip_str = '.'.join(parts)
        try:
            for p in parts:
                v = int(p)
                if not (0 <= v <= 255):
                    raise ValueError
        except ValueError:
            self._err(f"Invalid IP address: {ip_str!r}", start_line, start_col)
            # Invalid IPv4 literals must not be emitted as valid IP_ADDRESS tokens.
            return False
        return Token(TK_IP_ADDRESS, ip_str, start_line, start_col)

    def _read_number_or_ip(self):
        """Read an INTEGER or IP_ADDRESS token."""
        line, col = self._here()
        start = self.pos
        while self._cur() and self._cur().isdigit():
            self._advance()
        digits = self.source[start:self.pos]

        # Look ahead: if next char is '.', try to parse as IP
        if self._cur() == '.':
            ip_result = self._try_read_ip(digits, line, col)
            if ip_result is False:
                return None
            if ip_result:
                return ip_result

            # This is a malformed dotted numeric literal (e.g. 80., 1.2.3):
            # consume the whole malformed literal and emit a precise lexer error.
            while self._cur() and (self._cur().isdigit() or self._cur() == '.'):
                self._advance()
            malformed = self.source[start:self.pos]
            self._err(
                f"Malformed numeric literal {malformed!r}: dotted numeric literals "
                f"must be valid IPv4 addresses in the form a.b.c.d with octets 0-255",
                line, col
            )
            return None
        return Token(TK_INTEGER, digits, line, col)

    def _skip_comment(self):
        """Skip from # to end of line."""
        while self._cur() and self._cur() != '\n':
            self._advance()

    # ── main loop ─────────────────────────────────────────────────────────────

    def tokenize(self):
        """
        Returns (token_list, error_list).
        token_list always ends with an EOF token.
        error_list may be non-empty even when token_list is useful
        (the scanner continues after errors).
        """
        while self.pos < len(self.source):
            ch   = self._cur()
            line = self.line
            col  = self.col

            # whitespace
            if ch.isspace():
                self._advance()
                continue

            # comment
            if ch == '#':
                self._skip_comment()
                continue

            # word (keyword / field / ident)
            if ch.isalpha() or ch == '_':
                self.tokens.append(self._read_word())
                continue

            # number or IP
            if ch.isdigit():
                tok = self._read_number_or_ip()
                if tok is not None:
                    self.tokens.append(tok)
                continue

            # quoted text is invalid in this grammar; keep it as a lexical error
            if ch == '"':
                self._err(f"Unexpected character: {ch!r}", line, col)
                self._advance()
                continue

            # two-char operators (must precede single-char)
            if ch == '=' and self._peek() == '=':
                self._advance(); self._advance()
                self.tokens.append(Token(TK_EQ, '==', line, col))
                continue
            if ch == '!' and self._peek() == '=':
                self._advance(); self._advance()
                self.tokens.append(Token(TK_NEQ, '!=', line, col))
                continue
            if ch == '<' and self._peek() == '=':
                self._advance(); self._advance()
                self.tokens.append(Token(TK_LTE, '<=', line, col))
                continue
            if ch == '>' and self._peek() == '=':
                self._advance(); self._advance()
                self.tokens.append(Token(TK_GTE, '>=', line, col))
                continue

            # single-char operators
            if ch == '<':
                self._advance()
                self.tokens.append(Token(TK_LT, '<', line, col))
                continue
            if ch == '>':
                self._advance()
                self.tokens.append(Token(TK_GT, '>', line, col))
                continue

            # punctuation
            punc_map = {
                '{': TK_LBRACE, '}': TK_RBRACE,
                '(': TK_LPAREN, ')': TK_RPAREN,
                ';': TK_SEMI,
            }
            if ch in punc_map:
                self._advance()
                self.tokens.append(Token(punc_map[ch], ch, line, col))
                continue

            # unknown
            self._err(f"Unexpected character: {ch!r}", line, col)
            self._advance()

        self.tokens.append(Token(TK_EOF, '', self.line, self.col))
        return self.tokens, self.errors
