import unittest

from lexer import Lexer


class LexerIPv4Tests(unittest.TestCase):
    def test_valid_ipv4_literal_is_accepted(self):
        tokens, errors = Lexer("IF source_ip == 192.168.1.10 THEN ALLOW;").tokenize()
        self.assertFalse(errors)
        self.assertIn(
            ('IP_ADDRESS', '192.168.1.10'),
            [(tok.ttype, tok.value) for tok in tokens],
        )

    def test_invalid_ipv4_literal_raises_lexical_error_and_no_ip_token(self):
        tokens, errors = Lexer("IF source_ip == 192.168.1.999 THEN ALLOW;").tokenize()
        self.assertTrue(errors)
        self.assertTrue(any("Invalid IP address: '192.168.1.999'" in str(e) for e in errors))
        self.assertNotIn(
            ('IP_ADDRESS', '192.168.1.999'),
            [(tok.ttype, tok.value) for tok in tokens],
        )

    def test_malformed_numeric_literal_has_clear_lexical_error(self):
        for src in [
            "IF source_ip == 80. THEN ALLOW;",
            "IF source_ip == 1.2.3 THEN ALLOW;",
        ]:
            tokens, errors = Lexer(src).tokenize()
            self.assertTrue(errors)
            self.assertTrue(any("Malformed numeric literal" in str(e) for e in errors))
            self.assertNotIn(
                ('IP_ADDRESS', src.split('==')[-1].strip().rstrip(';')),
                [(tok.ttype, tok.value) for tok in tokens],
            )


if __name__ == '__main__':
    unittest.main()
