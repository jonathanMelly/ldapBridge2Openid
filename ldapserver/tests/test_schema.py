import unittest
import datetime

import ldapserver
from ldapserver.schema.types import OIDDict, Schema
from ldapserver.schema import syntaxes, matching_rules

class TestOIDDict(unittest.TestCase):
	def test_lookup(self):
		class TestObj:
			pass
		oiddict = OIDDict()
		obj1 = TestObj()
		oiddict._register(obj1, '1.1.0', '1.1.0')
		obj2 = TestObj()
		oiddict._register(obj2, '1.1.1', 'fooBar', 'foo', 'bar')
		obj3 = TestObj()
		oiddict._register(obj3, '1.1.2', 'test', 'test')
		self.assertIs(oiddict[obj1], obj1)
		self.assertIs(oiddict['1.1.0'], obj1)
		self.assertIs(oiddict[obj2], obj2)
		self.assertIs(oiddict['1.1.1'], obj2)
		self.assertIs(oiddict['fooBar'], obj2)
		self.assertIs(oiddict['foobar'], obj2)
		self.assertIs(oiddict['foo'], obj2)
		self.assertIs(oiddict['bar'], obj2)
		self.assertIs(oiddict[obj3], obj3)
		self.assertIs(oiddict['1.1.2'], obj3)
		self.assertIs(oiddict['test'], obj3)
		self.assertEqual(len(oiddict), 3)
		self.assertEqual(set(oiddict), {'1.1.0', 'fooBar', 'test'})
		self.assertIs(oiddict.get_numeric_oid(obj1), '1.1.0')
		self.assertIs(oiddict.get_numeric_oid('1.1.0'), '1.1.0')
		self.assertIs(oiddict.get_numeric_oid(obj2), '1.1.1')
		self.assertIs(oiddict.get_numeric_oid('1.1.1'), '1.1.1')
		self.assertIs(oiddict.get_numeric_oid('fooBar'), '1.1.1')
		self.assertIs(oiddict.get_numeric_oid('foobar'), '1.1.1')
		self.assertIs(oiddict.get_numeric_oid('foo'), '1.1.1')
		self.assertIs(oiddict.get_numeric_oid('bar'), '1.1.1')
		self.assertIs(oiddict.get_numeric_oid(obj3), '1.1.2')
		self.assertIs(oiddict.get_numeric_oid('1.1.2'), '1.1.2')
		self.assertIs(oiddict.get_numeric_oid('test'), '1.1.2')

	def test_uniqueness(self):
		class TestObj:
			pass
		oiddict = OIDDict()
		obj1 = TestObj()
		oiddict._register(obj1, '1.1.0', 'foo', 'bar')
		# Duplicate registration of the same obj is ok
		oiddict._register(obj1, '1.1.0', 'foo', 'bar')
		obj2 = TestObj()
		# Duplicate registration of another obj with the same name/OID is not ok
		with self.assertRaises(Exception):
			oiddict._register(obj2, '1.1.0', 'fooBar')
		with self.assertRaises(Exception):
			oiddict._register(obj2, '1.1.1', 'fooBar', 'foo', 'test')

class TestSchema(unittest.TestCase):
	def test_syntax_registration(self):
		schema = Schema(syntax_definitions=[syntaxes.DirectoryString])
		self.assertEqual(len(schema), 1)
		self.assertEqual(len(schema.syntaxes), 1)
		self.assertIn(syntaxes.DirectoryString.oid, schema)
		self.assertIn(syntaxes.DirectoryString.oid, schema.syntaxes)
		syntax = schema[syntaxes.DirectoryString.oid]
		self.assertIs(syntax.schema, schema)
		self.assertEqual(syntax.definition, syntaxes.DirectoryString)
		self.assertEqual(syntax.oid, syntaxes.DirectoryString.oid)
		self.assertEqual(syntax.ref, syntaxes.DirectoryString.oid)
		self.assertEqual(syntax.compatible_matching_rules, set())

	def test_matching_rule_registration(self):
		syntax_definitions = [
			syntaxes.DirectoryString,
			syntaxes.TelephoneNumber,
		]
		matching_rule_definitions = [
			matching_rules.caseExactMatch,
			matching_rules.telephoneNumberMatch,
		]
		schema = Schema(syntax_definitions=syntax_definitions,
		                matching_rule_definitions=matching_rule_definitions)
		self.assertEqual(len(schema), 4)
		self.assertEqual(len(schema.syntaxes), 2)
		self.assertEqual(len(schema.matching_rules), 2)
		self.assertIn(matching_rules.caseExactMatch.oid, schema)
		self.assertIn(matching_rules.caseExactMatch.oid, schema.matching_rules)
		for name in matching_rules.caseExactMatch.name:
			self.assertIn(name, schema.matching_rules)
		matching_rule = schema[matching_rules.caseExactMatch.oid]
		self.assertIs(matching_rule.schema, schema)
		self.assertEqual(matching_rule.definition, matching_rules.caseExactMatch)
		self.assertEqual(matching_rule.oid, matching_rules.caseExactMatch.oid)
		self.assertIs(matching_rule.syntax, schema[syntaxes.DirectoryString.oid])
		self.assertEqual(matching_rule.names, matching_rules.caseExactMatch.name)
		self.assertEqual(matching_rule.ref, matching_rules.caseExactMatch.name[0])
		self.assertEqual(matching_rule.compatible_syntaxes, {schema[syntaxes.TelephoneNumber.oid],
		                                                     schema[syntaxes.DirectoryString.oid]})
		self.assertEqual(schema[syntaxes.TelephoneNumber.oid].compatible_matching_rules, {matching_rule, schema['telephoneNumberMatch']})
		self.assertEqual(schema[syntaxes.DirectoryString.oid].compatible_matching_rules, {matching_rule})

	def test_matching_rule_registration_unmet_deps(self):
		syntax_definitions = [
			syntaxes.TelephoneNumber,
		]
		matching_rule_definitions = [
			matching_rules.caseExactMatch,
		]
		with self.assertRaises(Exception):
			schema = Schema(syntax_definitions=syntax_definitions,
			                matching_rule_definitions=matching_rule_definitions)

	def test_attribute_type_registration(self):
		syntax_definitions = [
			syntaxes.DirectoryString,
			syntaxes.SubstringAssertion,
		]
		matching_rule_definitions = [
			matching_rules.caseIgnoreMatch,
			matching_rules.caseIgnoreSubstringsMatch,
			matching_rules.caseExactMatch,
		]
		attribute_type_definitions = [
			"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )",
		]
		schema = Schema(syntax_definitions=syntax_definitions,
		                matching_rule_definitions=matching_rule_definitions,
		                attribute_type_definitions=attribute_type_definitions)
		self.assertEqual(len(schema), 7)
		self.assertEqual(len(schema.syntaxes), 2)
		self.assertEqual(len(schema.matching_rules), 3)
		self.assertEqual(len(schema.attribute_types), 2)
		for name in ['2.5.4.3', 'cn', 'commonName']:
			self.assertIn(name, schema)
			self.assertIn(name, schema.attribute_types)
		attribute_type = schema['cn']
		self.assertIs(attribute_type.schema, schema)
		self.assertEqual(attribute_type.oid, '2.5.4.3')
		self.assertEqual(attribute_type.names, ['cn', 'commonName'])
		self.assertEqual(attribute_type.ref, 'cn')
		self.assertEqual(attribute_type.sup, schema['name'])
		self.assertEqual(attribute_type.subtypes, set())
		self.assertEqual(schema['name'].subtypes, {attribute_type})
		self.assertEqual(attribute_type.equality, schema['caseIgnoreMatch'])
		self.assertIsNone(attribute_type.ordering)
		self.assertEqual(attribute_type.substr, schema['caseIgnoreSubstringsMatch'])
		self.assertFalse(attribute_type.is_operational)
		self.assertIn(attribute_type, schema.user_attribute_types)
		self.assertEqual(attribute_type.compatible_matching_rules,
		                 {schema['caseIgnoreMatch'], schema['caseIgnoreSubstringsMatch'], schema['caseExactMatch']})
		self.assertIn(attribute_type, schema['caseIgnoreMatch'].compatible_attribute_types)
		self.assertIn(attribute_type, schema['caseIgnoreSubstringsMatch'].compatible_attribute_types)
		self.assertIn(attribute_type, schema['caseExactMatch'].compatible_attribute_types)

	def test_attribute_type_registration_wrong_order(self):
		syntax_definitions = [
			syntaxes.DirectoryString,
			syntaxes.SubstringAssertion,
		]
		matching_rule_definitions = [
			matching_rules.caseIgnoreMatch,
			matching_rules.caseIgnoreSubstringsMatch,
			matching_rules.caseExactMatch,
		]
		attribute_type_definitions = [
			"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )",
			"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		]
		schema = Schema(syntax_definitions=syntax_definitions,
		                matching_rule_definitions=matching_rule_definitions,
		                attribute_type_definitions=attribute_type_definitions)
		self.assertEqual(len(schema), 7)
		self.assertEqual(len(schema.syntaxes), 2)
		self.assertEqual(len(schema.matching_rules), 3)
		self.assertEqual(len(schema.attribute_types), 2)

	def test_object_class_registration(self):
		syntax_definitions = [
			syntaxes.DN,
			syntaxes.OID,
		]
		matching_rule_definitions = [
			matching_rules.distinguishedNameMatch,
			matching_rules.objectIdentifierMatch,
		]
		attribute_type_definitions = [
			"( 2.5.4.1 NAME 'aliasedObjectName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
			"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		]
		object_class_definitions = [
			"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
			"( 2.5.6.1 NAME 'alias' SUP top STRUCTURAL MUST aliasedObjectName )",
		]
		schema = Schema(syntax_definitions=syntax_definitions,
		                matching_rule_definitions=matching_rule_definitions,
		                attribute_type_definitions=attribute_type_definitions,
		                object_class_definitions=object_class_definitions)
		self.assertEqual(len(schema), 8)
		self.assertEqual(len(schema.syntaxes), 2)
		self.assertEqual(len(schema.matching_rules), 2)
		self.assertEqual(len(schema.attribute_types), 2)
		self.assertEqual(len(schema.object_classes), 2)

	def test_object_class_registration_wrong_order(self):
		syntax_definitions = [
			syntaxes.DN,
			syntaxes.OID,
		]
		matching_rule_definitions = [
			matching_rules.distinguishedNameMatch,
			matching_rules.objectIdentifierMatch,
		]
		attribute_type_definitions = [
			"( 2.5.4.1 NAME 'aliasedObjectName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
			"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		]
		object_class_definitions = [
			"( 2.5.6.1 NAME 'alias' SUP top STRUCTURAL MUST aliasedObjectName )",
			"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		]
		schema = Schema(syntax_definitions=syntax_definitions,
		                matching_rule_definitions=matching_rule_definitions,
		                attribute_type_definitions=attribute_type_definitions,
		                object_class_definitions=object_class_definitions)
		self.assertEqual(len(schema), 8)
		self.assertEqual(len(schema.syntaxes), 2)
		self.assertEqual(len(schema.matching_rules), 2)
		self.assertEqual(len(schema.attribute_types), 2)
		self.assertEqual(len(schema.object_classes), 2)

	def test_object_extend(self):
		syntax_definitions = [
			syntaxes.DN,
			syntaxes.OID,
		]
		matching_rule_definitions = [
			matching_rules.distinguishedNameMatch,
			matching_rules.objectIdentifierMatch,
		]
		attribute_type_definitions = [
			"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		]
		object_class_definitions = [
			"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		]
		schema = Schema(syntax_definitions=syntax_definitions,
		                matching_rule_definitions=matching_rule_definitions,
		                attribute_type_definitions=attribute_type_definitions,
		                object_class_definitions=object_class_definitions)
		self.assertEqual(len(schema), 6)
		self.assertEqual(len(schema.syntaxes), 2)
		self.assertEqual(len(schema.matching_rules), 2)
		self.assertEqual(len(schema.attribute_types), 1)
		self.assertEqual(len(schema.object_classes), 1)
		attribute_type_definitions = [
			"( 2.5.4.1 NAME 'aliasedObjectName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
		]
		object_class_definitions = [
			"( 2.5.6.1 NAME 'alias' SUP top STRUCTURAL MUST aliasedObjectName )",
		]
		schema = schema.extend(attribute_type_definitions=attribute_type_definitions,
		                       object_class_definitions=object_class_definitions)
		self.assertEqual(len(schema), 8)
		self.assertEqual(len(schema.syntaxes), 2)
		self.assertEqual(len(schema.matching_rules), 2)
		self.assertEqual(len(schema.attribute_types), 2)
		self.assertEqual(len(schema.object_classes), 2)
		self.assertEqual(schema['distinguishedNameMatch'].compatible_attribute_types,
		                 {schema['aliasedObjectName']})

	def test_or(self):
		syntax_definitions0 = [
			syntaxes.DN,
			syntaxes.OID,
			syntaxes.DirectoryString,
			syntaxes.SubstringAssertion,
		]
		matching_rule_definitions0 = [
			matching_rules.distinguishedNameMatch,
			matching_rules.objectIdentifierMatch,
			matching_rules.caseIgnoreMatch,
			matching_rules.caseIgnoreSubstringsMatch,
		]
		attribute_type_definitions0 = [
			"( 2.5.4.1 NAME 'aliasedObjectName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
			"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
			"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		]
		object_class_definitions0 = [
			"( 2.5.6.1 NAME 'alias' SUP top STRUCTURAL MUST aliasedObjectName )",
			"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		]
		schema0 = Schema(syntax_definitions=syntax_definitions0,
		                 matching_rule_definitions=matching_rule_definitions0,
		                 attribute_type_definitions=attribute_type_definitions0,
		                 object_class_definitions=object_class_definitions0)
		syntax_definitions1 = [
			syntaxes.DirectoryString,
			syntaxes.OID,
		]
		matching_rule_definitions1 = [
			matching_rules.caseExactMatch,
			matching_rules.objectIdentifierMatch,
		]
		attribute_type_definitions1 = [
			"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
			"( 1.3.6.1.4.1.250.1.57 NAME 'labeledURI' DESC 'Uniform Resource Identifier with optional label' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		]
		object_class_definitions1 = [
			"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
			"( 1.3.6.1.4.1.250.3.15 NAME 'labeledURIObject' DESC 'object that contains the URI attribute type' SUP top AUXILIARY MAY labeledURI )",
		]
		schema1 = Schema(syntax_definitions=syntax_definitions1,
		                 matching_rule_definitions=matching_rule_definitions1,
		                 attribute_type_definitions=attribute_type_definitions1,
		                 object_class_definitions=object_class_definitions1)
		schema = schema0 | schema1
		self.assertEqual(len(schema.syntaxes), 4)
		self.assertEqual(len(schema.matching_rules), 5)
		self.assertEqual(len(schema.attribute_types), 4)
		self.assertEqual(len(schema.object_classes), 3)

class TestAttributeType(unittest.TestCase):
	schema = ldapserver.schema.RFC4519_SCHEMA

	def test_repr(self):
		self.assertIsInstance(repr(self.schema['cn']), str)

	def test_encode(self):
		self.assertEqual(self.schema['cn'].encode('foo äöü BAR'), b'foo \xc3\xa4\xc3\xb6\xc3\xbc BAR')

	def test_decode(self):
		self.assertEqual(self.schema['cn'].decode(b'foo \xc3\xa4\xc3\xb6\xc3\xbc BAR'), 'foo äöü BAR')

	def test_match_equal(self):
		self.assertFalse(self.schema['cn'].match_equal([], b'test'))
		self.assertFalse(self.schema['cn'].match_equal(['foo'], b'test'))
		self.assertTrue(self.schema['cn'].match_equal(['foo', 'bar', 'äöü'], b'\xc3\xa4\xc3\xb6\xc3\xbc '))
		self.assertTrue(self.schema['cn'].match_equal(['foo', 'bar', 'äöü'], b'BAR'))
		# objectIdentifierMatch actually uses data from the self.schema
		self.assertTrue(self.schema['objectclass'].match_equal(['2.5.6.0', 'Alias'], b'2.5.6.1'))
		self.assertTrue(self.schema['objectclass'].match_equal(['2.5.6.0', 'Alias'], b'tOp'))
		# 'facsimileTelephoneNumber' has no EQUALITY
		with self.assertRaises(ldapserver.exceptions.LDAPInappropriateMatching):
			self.schema['facsimileTelephoneNumber'].match_equal([b'test'], b'test')

	def test_match_substr(self):
		self.assertFalse(self.schema['cn'].match_substr([], b'test', [], None))
		self.assertFalse(self.schema['cn'].match_substr(['foo'], b'test', [], None))
		self.assertTrue(self.schema['cn'].match_substr(['foo', 'bar', 'äöü'], b'\xc3\xa4', [], None))
		self.assertTrue(self.schema['cn'].match_substr(['foo', 'bar', 'äöü'], None, [b'BA'], b'r '))
		# 'facsimileTelephoneNumber' has no SUBSTR
		with self.assertRaises(ldapserver.exceptions.LDAPInappropriateMatching):
			self.schema['facsimileTelephoneNumber'].match_substr([b'test'], b'test', [], None)

	def test_match_approx(self):
		# We don't have any matching rule that implementes a separate approx match, so ...
		self.assertFalse(self.schema['cn'].match_approx([], b'test'))
		self.assertFalse(self.schema['cn'].match_equal(['foo'], b'test'))
		self.assertTrue(self.schema['cn'].match_approx(['foo', 'bar', 'äöü'], b'\xc3\xa4\xc3\xb6\xc3\xbc '))
		self.assertTrue(self.schema['cn'].match_approx(['foo', 'bar', 'äöü'], b'BAR'))
		# objectIdentifierMatch actually uses data from the schema
		self.assertTrue(self.schema['objectclass'].match_approx(['2.5.6.0', 'Alias'], b'2.5.6.1'))
		self.assertTrue(self.schema['objectclass'].match_approx(['2.5.6.0', 'Alias'], b'tOp'))
		# 'facsimileTelephoneNumber' has no EQUALITY
		with self.assertRaises(ldapserver.exceptions.LDAPInappropriateMatching):
			self.schema['facsimileTelephoneNumber'].match_approx([b'test'], b'test')

	def test_match_greater_or_equal(self):
		self.assertTrue(self.schema['createTimestamp'].match_greater_or_equal([datetime.datetime.fromtimestamp(100, datetime.timezone.utc)], b'19700101000140Z'))
		self.assertTrue(self.schema['createTimestamp'].match_greater_or_equal([datetime.datetime.fromtimestamp(100, datetime.timezone.utc)], b'19700101000000Z'))
		self.assertFalse(self.schema['createTimestamp'].match_greater_or_equal([datetime.datetime.fromtimestamp(100, datetime.timezone.utc)], b'19700201000140Z'))
		# 'cn' has no ORDERING
		with self.assertRaises(ldapserver.exceptions.LDAPInappropriateMatching):
			self.schema['cn'].match_greater_or_equal(['test'], b'test')

	def test_match_less_or_equal(self):
		self.assertTrue(self.schema['createTimestamp'].match_less_or_equal([datetime.datetime.fromtimestamp(100, datetime.timezone.utc)], b'19700101000140Z'))
		self.assertFalse(self.schema['createTimestamp'].match_less_or_equal([datetime.datetime.fromtimestamp(100, datetime.timezone.utc)], b'19700101000000Z'))
		self.assertTrue(self.schema['createTimestamp'].match_less_or_equal([datetime.datetime.fromtimestamp(100, datetime.timezone.utc)], b'19700201000140Z'))
		# 'cn' has no ORDERING, but <= is a hybrid of ORDERING and EQUALITY
		self.schema['cn'].match_less_or_equal(['test'], b'test')
		# 'facsimileTelephoneNumber' has no EQUALITY/ORDERING
		with self.assertRaises(ldapserver.exceptions.LDAPInappropriateMatching):
			self.schema['facsimileTelephoneNumber'].match_less_or_equal([b'test'], b'test')

	def test_match_extensible(self):
		self.assertTrue(self.schema['cn'].match_extensible(['test'], b'Test', None))
		self.assertTrue(self.schema['cn'].match_extensible(['test'], b'Test', self.schema['caseIgnoreMatch']))
		self.assertFalse(self.schema['cn'].match_extensible(['test'], b'Test', self.schema['caseExactMatch']))
		self.assertTrue(self.schema['cn'].match_extensible(['test'], b'test', self.schema['caseExactMatch']))
		# 'facsimileTelephoneNumber' has no EQUALITY (with match_extensible defaults to)
		with self.assertRaises(ldapserver.exceptions.LDAPInappropriateMatching):
			self.schema['facsimileTelephoneNumber'].match_extensible([b'test'], b'test', None)
		# Incompatible matching
		with self.assertRaises(ldapserver.exceptions.LDAPInappropriateMatching):
			self.schema['cn'].match_extensible([b'test'], b'7', self.schema['integerMatch'])
