import unittest

from lexer import Lexer
from parser import Parser


class CaseSensitiveFieldTests(unittest.TestCase):
    def test_canonical_protocol_field_is_accepted(self):
        src = "POLICY p { RULE r { IF protocol == TCP THEN ALLOW; } }"
        tokens, errors = Lexer(src).tokenize()
        self.assertFalse(errors)
        self.assertEqual(tokens[7].ttype, 'protocol')
        self.assertEqual(tokens[7].value, 'protocol')

    def test_mixed_case_protocol_field_is_rejected(self):
        src = "POLICY p { RULE r { IF Protocol == TCP THEN ALLOW; } }"
        tokens, errors = Lexer(src).tokenize()
        self.assertFalse(errors)
        self.assertEqual(tokens[7].ttype, 'IDENT')
        self.assertEqual(tokens[7].value, 'Protocol')
        self.assertFalse(any(tok.ttype == 'protocol' for tok in tokens))
        parser = Parser(tokens)
        parser.parse()
        self.assertTrue(parser.errors)
        self.assertIn('Expected a network field', str(parser.errors[0]))


if __name__ == '__main__':
    unittest.main()
