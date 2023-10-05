import unittest
import enum

from ldapserver.rfc4518_stringprep import prepare, MatchingType, SubstringType

class TestStringprep(unittest.TestCase):
	def test_map(self):
		# [...] COMBINING GRAPHEME JOINER (U+034F) [...] code points are also mapped to nothing.
		self.assertEqual(prepare(' foo\u034Fbar ', MatchingType.EXACT_STRING, SubstringType.NONE), ' foobar ')
		# [...] LINE FEED (LF) (U+000A) [...] are mapped to SPACE (U+0020).
		self.assertEqual(prepare(' foo\n\rbar ', MatchingType.EXACT_STRING, SubstringType.NONE), ' foo  bar ')
		# For case ignore, numeric, and stored prefix string matching rules,
		# characters are case folded per B.2 of [RFC3454].
		self.assertEqual(prepare(' FooBar ', MatchingType.CASE_IGNORE_STRING, SubstringType.NONE), ' foobar ')
		# Not that a valid numeric string can contain any characters affected by case-folding?!
		self.assertEqual(prepare('FooBar', MatchingType.NUMERIC_STRING, SubstringType.NONE), 'foobar')

	def test_normalize(self):
		self.assertEqual(prepare(' \u00C5 ', MatchingType.EXACT_STRING, SubstringType.NONE), ' \u00C5 ')
		self.assertEqual(prepare(' \u212B ', MatchingType.EXACT_STRING, SubstringType.NONE), ' \u00C5 ')
		self.assertEqual(prepare(' \u0041\u030A ', MatchingType.EXACT_STRING, SubstringType.NONE), ' \u00C5 ')

	def test_check_prohibited(self):
		with self.assertRaises(ValueError):
			prepare(' foo \uFFFD bar ', MatchingType.EXACT_STRING, SubstringType.NONE)

	def test_insignificant_characters(self):
		self.assertEqual(prepare('foo bar', MatchingType.EXACT_STRING, SubstringType.NONE), ' foo  bar ')
		# Test special case of SPACE followed by combining mark
		self.assertEqual(prepare('foo \u030A bar', MatchingType.EXACT_STRING, SubstringType.NONE), ' foo \u030A  bar ')
		self.assertEqual(prepare(' \u030A foobar', MatchingType.EXACT_STRING, SubstringType.NONE), '  \u030A  foobar ')
		self.assertEqual(prepare('foobar \u030A', MatchingType.EXACT_STRING, SubstringType.NONE), ' foobar \u030A ')
		# Not that a numeric string or a telephone number can contain any combining
		# marks, but the RFC says that SPACES followed by combining marks are
		# special, so ...?!
		self.assertEqual(prepare('foo \u030A bar', MatchingType.NUMERIC_STRING), 'foo \u030Abar')
		self.assertEqual(prepare('foo \u030A bar', MatchingType.TELEPHONE_NUMBER), 'foo \u030Abar')

		# Examples from RFC4518 for "Insignificant Character Handling"
		self.assertEqual(prepare('foo bar  ', MatchingType.EXACT_STRING, SubstringType.NONE), ' foo  bar ')
		self.assertEqual(prepare('foo bar  ', MatchingType.EXACT_STRING, SubstringType.INITIAL), ' foo  bar ')
		self.assertEqual(prepare('foo bar  ', MatchingType.EXACT_STRING, SubstringType.ANY), 'foo  bar ')
		self.assertEqual(prepare('  123  456  ', MatchingType.NUMERIC_STRING), '123456')
		self.assertEqual(prepare('   ', MatchingType.NUMERIC_STRING), '')
		self.assertEqual(prepare(' -123  456 -', MatchingType.TELEPHONE_NUMBER), '123456')
		self.assertEqual(prepare('---', MatchingType.TELEPHONE_NUMBER), '')
