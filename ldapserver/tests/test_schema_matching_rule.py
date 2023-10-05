import unittest

import ldapserver
from ldapserver.schema import matching_rules

class TestGenericEqualityMatchingRule(unittest.TestCase):
	def test_match_equal(self):
		rule = matching_rules.integerMatch
		self.assertTrue(rule.match_equal(None, [1234], 1234))
		self.assertFalse(rule.match_equal(None, [4321], 1234))
		self.assertFalse(rule.match_equal(None, [1234], 4321))
		self.assertTrue(rule.match_equal(None, [0, 1], 0))
		self.assertTrue(rule.match_equal(None, [0, 1], 1))
		self.assertFalse(rule.match_equal(None, [0, 1], -1))
		self.assertFalse(rule.match_equal(None, [0, 1], 2))
		self.assertFalse(rule.match_equal(None, [], 1))

class TestGenericOrderingMatchingRule(unittest.TestCase):
	def test_match_less(self):
		rule = matching_rules.integerOrderingMatch
		self.assertFalse(rule.match_less(None, [1234], 1234))
		self.assertFalse(rule.match_less(None, [4321], 1234))
		self.assertTrue(rule.match_less(None, [1234], 4321))
		self.assertFalse(rule.match_less(None, [0, 1], 0))
		self.assertTrue(rule.match_less(None, [0, 1], 1))
		self.assertFalse(rule.match_less(None, [0, 1], -1))
		self.assertTrue(rule.match_less(None, [0, 1], 2))
		self.assertFalse(rule.match_less(None, [], 1))

	def test_match_greater_or_equal(self):
		rule = matching_rules.integerOrderingMatch
		self.assertTrue(rule.match_greater_or_equal(None, [1234], 1234))
		self.assertTrue(rule.match_greater_or_equal(None, [4321], 1234))
		self.assertFalse(rule.match_greater_or_equal(None, [1234], 4321))
		self.assertTrue(rule.match_greater_or_equal(None, [0, 1], 0))
		self.assertTrue(rule.match_greater_or_equal(None, [0, 1], 1))
		self.assertTrue(rule.match_greater_or_equal(None, [0, 1], -1))
		self.assertFalse(rule.match_greater_or_equal(None, [0, 1], 2))
		self.assertFalse(rule.match_greater_or_equal(None, [], 1))

class TestStringEqualityMatchingRule(unittest.TestCase):
	def test_match_equal(self):
		rule = matching_rules.caseIgnoreMatch
		self.assertTrue(rule.match_equal(None, ['foo', 'Bar'], 'foo'))
		self.assertFalse(rule.match_equal(None, ['foo', 'Bar'], 'foobar'))
		self.assertFalse(rule.match_equal(None, [], 'foo'))
		self.assertTrue(rule.match_equal(None, ['foo', 'Bar'], 'Bar'))
		self.assertTrue(rule.match_equal(None, ['foo', 'Bar'], 'Foo'))
		self.assertTrue(rule.match_equal(None, ['foo', 'Bar'], 'bar'))
		self.assertTrue(rule.match_equal(None, ['fo  o ', ' bar'], '   bar   '))
		self.assertFalse(rule.match_equal(None, ['fo  o ', ' b ar'], '   bar   '))
		self.assertTrue(rule.match_equal(None, ['fo\n\ro ', ' bar'], ' fo o'))
		rule = matching_rules.caseExactMatch
		self.assertTrue(rule.match_equal(None, ['foo', 'Bar'], 'foo'))
		self.assertFalse(rule.match_equal(None, ['foo', 'Bar'], 'foobar'))
		self.assertFalse(rule.match_equal(None, [], 'foo'))
		self.assertTrue(rule.match_equal(None, ['foo', 'Bar'], 'Bar'))
		self.assertFalse(rule.match_equal(None, ['foo', 'Bar'], 'Foo'))
		self.assertFalse(rule.match_equal(None, ['foo', 'Bar'], 'bar'))
		self.assertTrue(rule.match_equal(None, ['fo  o ', ' bar'], '   bar   '))
		self.assertFalse(rule.match_equal(None, ['fo  o ', ' b ar'], '   bar   '))
		self.assertTrue(rule.match_equal(None, ['fo\n\ro ', ' bar'], ' fo o'))
		# Prohibited characters make an attribute value unmatchable, but should not cause errors
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			rule.match_equal(None, ['foobar\uFFFD', 'test'], 'foobar\uFFFD')
		self.assertTrue(rule.match_equal(None, ['foobar\uFFFD', 'test'], 'test'))
		# Systematic tests for stringprep in test_stringprep.py

class TestStringOrderingMatchingRule(unittest.TestCase):
	def test_match_less(self):
		rule = matching_rules.caseIgnoreOrderingMatch
		self.assertFalse(rule.match_less(None, ['abc'], 'abc'))
		self.assertFalse(rule.match_less(None, [], 'abc'))
		self.assertTrue(rule.match_less(None, ['abc'], 'def'))
		self.assertTrue(rule.match_less(None, ['abc'], 'acd'))
		self.assertTrue(rule.match_less(None, ['def', 'abc'], 'acd'))
		self.assertTrue(rule.match_less(None, ['A'], 'b'))
		self.assertFalse(rule.match_less(None, ['a'], 'A'))
		self.assertFalse(rule.match_less(None, ['C'], 'a'))
		rule = matching_rules.caseExactOrderingMatch
		self.assertFalse(rule.match_less(None, ['abc'], 'abc'))
		self.assertFalse(rule.match_less(None, [], 'abc'))
		self.assertTrue(rule.match_less(None, ['abc'], 'def'))
		self.assertTrue(rule.match_less(None, ['abc'], 'acd'))
		self.assertTrue(rule.match_less(None, ['def', 'abc'], 'acd'))
		self.assertTrue(rule.match_less(None, ['A'], 'b'))
		self.assertFalse(rule.match_less(None, ['a'], 'A'))
		self.assertTrue(rule.match_less(None, ['C'], 'a'))
		# Systematic tests for stringprep in test_stringprep.py

	def test_match_greater_or_equal(self):
		rule = matching_rules.caseIgnoreOrderingMatch
		self.assertTrue(rule.match_greater_or_equal(None, ['abc'], 'abc'))
		self.assertFalse(rule.match_greater_or_equal(None, [], 'abc'))
		self.assertFalse(rule.match_greater_or_equal(None, ['abc'], 'def'))
		self.assertFalse(rule.match_greater_or_equal(None, ['abc'], 'acd'))
		self.assertTrue(rule.match_greater_or_equal(None, ['def', 'abc'], 'acd'))
		self.assertFalse(rule.match_greater_or_equal(None, ['A'], 'b'))
		self.assertTrue(rule.match_greater_or_equal(None, ['a'], 'A'))
		self.assertTrue(rule.match_greater_or_equal(None, ['C'], 'a'))
		rule = matching_rules.caseExactOrderingMatch
		self.assertTrue(rule.match_greater_or_equal(None, ['abc'], 'abc'))
		self.assertFalse(rule.match_greater_or_equal(None, [], 'abc'))
		self.assertFalse(rule.match_greater_or_equal(None, ['abc'], 'def'))
		self.assertFalse(rule.match_greater_or_equal(None, ['abc'], 'acd'))
		self.assertTrue(rule.match_greater_or_equal(None, ['def', 'abc'], 'acd'))
		self.assertFalse(rule.match_greater_or_equal(None, ['A'], 'b'))
		self.assertTrue(rule.match_greater_or_equal(None, ['a'], 'A'))
		self.assertFalse(rule.match_greater_or_equal(None, ['C'], 'a'))
		# Systematic tests for stringprep in test_stringprep.py

class TestStringSubstrMatchingRule(unittest.TestCase):
	def test_match_substr(self):
		rule = matching_rules.caseExactSubstringsMatch
		self.assertTrue(rule.match_substr(None, ['abcdefghi'], 'abcdefghi', [], None))
		self.assertTrue(rule.match_substr(None, ['foo', 'abcdefghi', 'bar'], 'abcdefghi', [], None))
		self.assertTrue(rule.match_substr(None, ['abcdefghi'], None, ['abcdefghi'], None))
		self.assertTrue(rule.match_substr(None, ['abcdefghi'], None, [], 'abcdefghi'))
		self.assertTrue(rule.match_substr(None, ['abcdefghi'], 'abc', ['def'], 'ghi'))
		self.assertTrue(rule.match_substr(None, ['abcdefghi'], 'abc', ['d', 'ef'], 'ghi'))
		self.assertFalse(rule.match_substr(None, ['abcdefghi'], 'abcd', ['d', 'ef'], 'ghi'))
		self.assertFalse(rule.match_substr(None, ['abcdefghi'], 'abc', ['cd', 'ef'], 'ghi'))
		self.assertFalse(rule.match_substr(None, ['abcdefghi'], 'abc', ['de', 'ef'], 'ghi'))
		self.assertFalse(rule.match_substr(None, ['abcdefghi'], 'abc', ['d', 'def'], 'ghi'))
		self.assertFalse(rule.match_substr(None, ['abcdefghi'], 'abc', ['d', 'efg'], 'ghi'))
		self.assertFalse(rule.match_substr(None, ['abcdefghi'], 'abc', ['d', 'ef'], 'fghi'))
		self.assertTrue(rule.match_substr(None, ['abcdefghi'], 'ab', ['def'], 'ghi'))
		self.assertTrue(rule.match_substr(None, ['abcdefghi'], 'abc', ['ef'], 'ghi'))
		self.assertTrue(rule.match_substr(None, ['abcdefghi'], 'abc', ['de'], 'ghi'))
		self.assertTrue(rule.match_substr(None, ['abcdefghi'], 'abc', ['def'], 'hi'))
		# Prohibited characters make an attribute value unmatchable, but should not cause errors
		self.assertFalse(rule.match_substr(None, ['foobar\uFFFD', 'test'], 'foobar', [], None))
		self.assertTrue(rule.match_substr(None, ['foobar\uFFFD', 'test'], 'test', [], None))
		# TODO: more systematic tests

class TestStringListEqualityMatchingRule(unittest.TestCase):
	def test_equal(self):
		rule = matching_rules.caseIgnoreListMatch
		self.assertFalse(rule.match_equal(None, [], ['foo', 'bar']))
		self.assertTrue(rule.match_equal(None, [['foo', 'bar']], ['foo', 'bar']))
		self.assertTrue(rule.match_equal(None, [['Foo', 'bar']], ['foo', 'BAR']))
		self.assertFalse(rule.match_equal(None, [['bar', 'foo']], ['foo', 'bar']))
		self.assertFalse(rule.match_equal(None, [['foo', 'bar']], ['foo']))
		self.assertTrue(rule.match_equal(None, [['first'], ['foo', 'bar']], ['foo', 'bar']))
		self.assertTrue(rule.match_equal(None, [['line'], ['foo', 'bar']], ['line']))

class TestStringListSubstrMatchingRule(unittest.TestCase):
	def test_match_substr(self):
		rule = matching_rules.caseIgnoreListSubstringsMatch
		self.assertFalse(rule.match_substr(None, [], None, ['foo'], None))
		self.assertTrue(rule.match_substr(None, [['foo', 'bar', 'baz']], 'foo', ['bar'], 'baz'))
		self.assertFalse(rule.match_substr(None, [['foo', 'bar', 'baz']], 'bar', [], None))
		self.assertTrue(rule.match_substr(None, [['foo', 'bar', 'baz']], 'FOO', [], None))
		self.assertTrue(rule.match_substr(None, [['foo', 'bar', 'baz']], None, ['bar'], 'baz'))
		self.assertTrue(rule.match_substr(None, [['foo', 'bar', 'baz']], 'foo', [], 'baz'))
		self.assertTrue(rule.match_substr(None, [['foo', 'bar', 'baz']], 'foo', ['bar'], None))
		self.assertTrue(rule.match_substr(None, [['foo', 'bar', 'baz']], None, ['foo', 'bar', 'baz'], None))
		self.assertTrue(rule.match_substr(None, [['foo', 'bar', 'baz']], 'f', ['b', 'r'], 'z'))
		self.assertTrue(rule.match_substr(None, [['foo', 'bar']], None, ['foo', 'bar'], None))
		self.assertFalse(rule.match_substr(None, [['foo', 'bar']], None, ['foobar'], None))
		self.assertFalse(rule.match_substr(None, [['foo', 'bar']], None, ['foo bar'], None))
		# LF is internally used as a separator
		self.assertFalse(rule.match_substr(None, [['foo', 'bar']], None, ['foo\nbar'], None))

class TestFirstComponentMatchingRule(unittest.TestCase):
	def test_equal(self):
		class FirstCompontentIntegerValue:
			def __init__(self, integer):
				self.first_component_integer = integer
		rule = matching_rules.integerFirstComponentMatch
		self.assertTrue(rule.match_equal(None, [FirstCompontentIntegerValue(0), FirstCompontentIntegerValue(1)], 0))
		self.assertTrue(rule.match_equal(None, [FirstCompontentIntegerValue(0), FirstCompontentIntegerValue(1)], 1))
		self.assertFalse(rule.match_equal(None, [FirstCompontentIntegerValue(0), FirstCompontentIntegerValue(1)], 3))
		self.assertFalse(rule.match_equal(None, [], 1))

class TestOIDMatchingRule(unittest.TestCase):
	def test_equal(self):
		schema = ldapserver.schema.RFC4519_SCHEMA
		rule = matching_rules.objectIdentifierMatch
		self.assertTrue(rule.match_equal(schema, ['person', '2.5.6.2'], '2.5.6.6'))
		self.assertTrue(rule.match_equal(schema, ['person', '2.5.6.2'], 'Country'))
		self.assertFalse(rule.match_equal(schema, [], '2.5.6.6'))
		self.assertFalse(rule.match_equal(schema, [], 'Country'))
		self.assertTrue(rule.match_equal(schema, ['person', 'foobar'], 'person'))
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			rule.match_equal(schema, ['person'], 'foobar')
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			rule.match_equal(schema, ['person', 'foobar'], 'foobar')
		self.assertTrue(rule.match_equal(schema, ['person', '0.1.2.3.4'], '0.1.2.3.4'))
