import unittest
import datetime

import ldapserver
from ldapserver import DN, AttributeDict, ObjectEntry, RootDSE, SubschemaSubentry, EntryTemplate, WILDCARD, ldap

schema = ldapserver.schema.RFC4519_SCHEMA

class TestAttributeDict(unittest.TestCase):
	def test_init(self):
		AttributeDict(schema, cn=['foo', 'bar'], uid=[])

	def test_getitem(self):
		attrs = AttributeDict(schema, cn=['foo', 'bar'], uid=[])
		self.assertEqual(attrs['cn'], ['foo', 'bar'])
		self.assertEqual(attrs['CN'], ['foo', 'bar'])
		self.assertEqual(attrs['2.5.4.3'], ['foo', 'bar'])
		self.assertEqual(attrs[schema['cn']], ['foo', 'bar'])
		self.assertEqual(attrs['uid'], [])
		self.assertEqual(attrs['name'], [])
		self.assertEqual(attrs['objectClass'], [])
		attrs['objectClass'].append('top')
		self.assertEqual(attrs['objectClass'], ['top'])
		with self.assertRaises(KeyError):
			attrs['foobar']

	def test_get(self):
		attrs = AttributeDict(schema, cn=['foo', 'bar'], uid=[])
		self.assertEqual(attrs.get('cn'), ['foo', 'bar'])
		self.assertEqual(attrs.get('CN'), ['foo', 'bar'])
		self.assertEqual(attrs.get('2.5.4.3'), ['foo', 'bar'])
		self.assertEqual(attrs.get(schema['cn']), ['foo', 'bar'])
		self.assertEqual(attrs.get('uid'), [])
		self.assertEqual(attrs.get('uid', ['default']), ['default'])
		self.assertEqual(attrs.get('name'), [])
		self.assertEqual(attrs.get('name', ['default']), ['default'])
		self.assertEqual(attrs.get('name', subtypes=True), ['foo', 'bar'])
		self.assertEqual(attrs.get('foobar'), [])

	def test_contains(self):
		attrs = AttributeDict(schema, cn=['foo', 'bar'], uid=[])
		self.assertIn('cn', attrs)
		self.assertNotIn('uid', attrs)
		self.assertNotIn('objectClass', attrs)
		attrs['objectClass'].append('top')
		self.assertIn('objectClass', attrs)
		self.assertNotIn('foobar', attrs)

	def test_setitem(self):
		attrs = AttributeDict(schema, cn=['foo', 'bar'], uid=[])
		attrs['cn'] = ['bar', 'foo']
		self.assertEqual(attrs['cn'], ['bar', 'foo'])
		attrs['cn'] = []
		self.assertEqual(attrs['cn'], [])
		attrs['objectClass'] = []
		self.assertEqual(attrs['objectClass'], [])
		with self.assertRaises(KeyError):
			attrs['foobar'] = ['test']

	def test_delitem(self):
		attrs = AttributeDict(schema, cn=['foo', 'bar'], uid=[])
		del attrs['cn']
		self.assertEqual(attrs['cn'], [])
		del attrs['cn'] # does nothing
		with self.assertRaises(KeyError):
			del attrs['foobar']

	def test_iter(self):
		attrs = AttributeDict(schema, cn=['foo', 'bar'], uid=[])
		self.assertEqual(list(attrs), ['cn'])

	def test_len(self):
		attrs = AttributeDict(schema, cn=['foo', 'bar'], uid=[])
		self.assertEqual(len(attrs), 1)
		attrs['objectClass'] = ['top']
		self.assertEqual(len(attrs), 2)

	def test_keys(self):
		attrs = AttributeDict(schema, cn=['foo', 'bar'], uid=[], objectclass=['top'])
		self.assertEqual(set(attrs.keys()), {'cn', 'objectClass'})
		self.assertEqual(set(attrs.keys(types=True)), {schema['cn'], schema['objectClass']})

	def test_items(self):
		attrs = AttributeDict(schema, cn=['foo', 'bar'], uid=[], objectclass=['top'])
		self.assertEqual(list(sorted(attrs.items())), [('cn', ['foo', 'bar']), ('objectClass', ['top'])])
		self.assertIn((schema['cn'], ['foo', 'bar']), attrs.items(types=True))
		self.assertIn((schema['objectClass'], ['top']), attrs.items(types=True))

	def test_setdefault(self):
		attrs = AttributeDict(schema, cn=['foo', 'bar'], uid=[], objectclass=['top'])
		self.assertEqual(attrs.setdefault('CN', ['default']), ['foo', 'bar'])
		self.assertEqual(attrs['Cn'], ['foo', 'bar'])
		self.assertEqual(attrs.setdefault('c', ['default']), ['default'])
		self.assertEqual(attrs['c'], ['default'])

class TestObjectEntry(unittest.TestCase):
	def test_init(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'bar'], uid=[])
		self.assertEqual(obj.dn, DN.from_str(schema, 'cn=foo,dc=example,dc=com'))
		self.assertEqual(obj['cn'], ['foo', 'bar'])
		self.assertEqual(obj['uid'], [])

	def test_match_search_dn(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', objectclass=['top'])
		true_filter = ldap.FilterPresent('objectClass')

		scope = ldap.SearchScope.baseObject
		self.assertTrue(obj.match_search('cn=foo,dc=example,dc=com', scope, true_filter))
		self.assertFalse(obj.match_search('cn=bar,dc=example,dc=com', scope, true_filter))
		self.assertFalse(obj.match_search('dc=example,dc=com', scope, true_filter))
		self.assertFalse(obj.match_search('', scope, true_filter))
		self.assertFalse(obj.match_search('cn=test,cn=foo,dc=example,dc=com', scope, true_filter))

		scope = ldap.SearchScope.singleLevel
		self.assertFalse(obj.match_search('cn=foo,dc=example,dc=com', scope, true_filter))
		self.assertFalse(obj.match_search('cn=bar,dc=example,dc=com', scope, true_filter))
		self.assertTrue(obj.match_search('dc=example,dc=com', scope, true_filter))
		self.assertFalse(obj.match_search('', scope, true_filter))
		self.assertFalse(obj.match_search('cn=test,cn=foo,dc=example,dc=com', scope, true_filter))

		scope = ldap.SearchScope.wholeSubtree
		self.assertTrue(obj.match_search('cn=foo,dc=example,dc=com', scope, true_filter))
		self.assertFalse(obj.match_search('cn=bar,dc=example,dc=com', scope, true_filter))
		self.assertTrue(obj.match_search('dc=example,dc=com', scope, true_filter))
		self.assertTrue(obj.match_search('', scope, true_filter))
		self.assertFalse(obj.match_search('cn=test,cn=foo,dc=example,dc=com', scope, true_filter))

	def test_match_search_filter_present(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'bar'], uid=[], objectclass=['top'])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		# True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterPresent('ObjectClass')))
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterPresent('2.5.4.3'))) # OID
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterPresent('name'))) # subtype
		# False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterPresent('uid')))
		# Undefined (behaves like False)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterPresent('undefined')))

	def test_match_search_filter_not(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'bar'], uid=[], objectclass=['top'])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		# Not True = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterPresent('ObjectClass'))))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterPresent('2.5.4.3')))) # OID of cn
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterPresent('name')))) # subtype
		# Not False = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterPresent('uid'))))
		# Not Undefined = Undefined (behaves like False)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterPresent('undefined'))))

	def test_match_search_filter_and(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'bar'], uid=[], objectclass=['top'])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		true = ldap.FilterPresent('objectclass')
		false = ldap.FilterPresent('uid')
		undefined = ldap.FilterPresent('undefined')
		# True = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterAnd([true])))
		# True and True = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterAnd([true, true])))
		# True and False = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterAnd([true, false])))
		# False and False = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterAnd([false, false])))
		# False and Undefined = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterAnd([false, undefined])))
		# True and Undefined = Undefined (behaves like False)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterAnd([true, undefined])))
		# Empty And = True (RFC4526)
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterAnd([])))

		# Not True = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([true]))))
		# Not (True and True) = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([true, true]))))
		# Not (True and False) = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([true, false]))))
		# Not (False and False) = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([false, false]))))
		# Not (False and Undefined) = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([false, undefined]))))
		# Not (True and Undefined) = Undefined (behaves like False)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([true, undefined]))))
		# Not (Empty And) = False (RFC4526)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([]))))

	def test_match_search_filter_or(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'bar'], uid=[], objectclass=['top'])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		true = ldap.FilterPresent('objectclass')
		false = ldap.FilterPresent('uid')
		undefined = ldap.FilterPresent('undefined')
		# True = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterOr([true])))
		# True or True = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterOr([true, true])))
		# True or False = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterOr([true, false])))
		# False or False = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterOr([false, false])))
		# True or Undefined = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterOr([true, undefined])))
		# False or Undefined = Undefined (behaves like False)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterOr([false, undefined])))
		# Empty Or = False (RFC4526)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterOr([])))

		# Not True = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([true]))))
		# Not (True or True) = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([true, true]))))
		# Not (True or False) = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([true, false]))))
		# Not (False or False) = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([false, false]))))
		# Not (True or Undefined) = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([true, undefined]))))
		# Not (False or Undefined) = Undefined (behaves like False)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([false, undefined]))))
		# Not (Empty Or) = True (RFC4526)
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([]))))

	def test_match_search_filter_equal(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'bar'], uid=[], objectclass=['top'])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		# True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterEqual('ObjectClass', b'top')))
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterEqual('2.5.4.3', b'Foo'))) # OID
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterEqual('name', b'bar'))) # subtype
		# False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterEqual('ObjectClass', b'Person')))
		# Undefined (behaves like False)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterEqual('undefined', b'foo')))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterEqual('telexNumber', b'foo'))) # no EQUALITY
		# Not True = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('ObjectClass', b'top'))))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('2.5.4.3', b'Foo')))) # OID
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('name', b'bar')))) # subtype
		# Not False = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('ObjectClass', b'Person'))))
		# Not Undefined = Undefined (behaves like False)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('undefined', b'foo'))))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('telexNumber', b'foo')))) # no EQUALITY

	def test_match_search_filter_substr(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foobar', 'test'], uid=[], objectclass=['top'])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterSubstrings('cn', [ldap.InitialSubstring(b'foo')])))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterSubstrings('cn', [ldap.InitialSubstring(b'bar')])))
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterSubstrings('cn', [ldap.InitialSubstring(b'foo'), ldap.AnySubstring(b'b'), ldap.AnySubstring(b'a'), ldap.FinalSubstring(b'r')])))

	def test_match_search_filter_le(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo'], objectclass=['top'], createTimestamp=[datetime.datetime(1994, 12, 16, 10, 32, tzinfo=datetime.timezone.utc)])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterLessOrEqual('createTimestamp', b'199412161032Z')))
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterLessOrEqual('createTimestamp', b'199412161033Z')))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterLessOrEqual('createTimestamp', b'199412161031Z')))
		# LessOrEqual is hybrid between EQUALITY and ORDERING
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterLessOrEqual('cn', b'foo')))

	def test_match_search_filter_ge(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo'], objectclass=['top'], createTimestamp=[datetime.datetime(1994, 12, 16, 10, 32, tzinfo=datetime.timezone.utc)])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterGreaterOrEqual('createTimestamp', b'199412161032Z')))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterGreaterOrEqual('createTimestamp', b'199412161033Z')))
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterGreaterOrEqual('createTimestamp', b'199412161031Z')))
		# GreaterOrEqual is only ORDERING (which cn does not have)
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterGreaterOrEqual('cn', b'foo')))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterGreaterOrEqual('cn', b'foo'))))

	def test_match_search_filter_extensible_attribute_type(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'test'], uid=['foobar'], objectclass=['top'])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		# True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterExtensibleMatch(None, 'uid', b'Foobar', False)))
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'uid', b'Foobar', False)))
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreSubstringsMatch', 'uid', b'F*b*r', False)))
		# False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('caseExactMatch', 'uid', b'Foobar', False)))
		# Undefined
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('caseExactMatch', 'createTimestamp', b'199412161032Z', False)))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('generalizedTimeMatch', 'cn', b'199412161032Z', False)))
		# Not True = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch(None, 'uid', b'Foobar', False))))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'uid', b'Foobar', False))))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreSubstringsMatch', 'uid', b'F*b*r', False))))
		# Not False = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseExactMatch', 'uid', b'Foobar', False))))
		# Not Undefined = Undefined
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseExactMatch', 'createTimestamp', b'199412161032Z', False))))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('generalizedTimeMatch', 'cn', b'199412161032Z', False))))

	def test_match_search_filter_extensible_no_attribute_type(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'test'], uid=['foobar'], objectclass=['top'])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		# True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', None, b'foobar', False)))
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('objectIdentifierMatch', None, b'top', False)))
		# False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('objectIdentifierMatch', None, b'person', False)))
		# Undefined
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('octetStringOrderingMatch', None, b'someoctetstring', False)))
		# Not True = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', None, b'foobar', False))))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('objectIdentifierMatch', None, b'top', False))))
		# Not False = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('objectIdentifierMatch', None, b'person', False))))
		# Not Undefined = Undefined
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('octetStringOrderingMatch', None, b'someoctetstring', False))))

	def test_match_search_filter_extensible_dn(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'test'], uid=['foobar'], objectclass=['top'])
		dn = 'cn=foo,dc=example,dc=com'
		scope = ldap.SearchScope.baseObject
		obj = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD, uid=['foobar'])
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		# True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'example', True)))
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'uid', b'foobar', True))) # also matches regular attributes
		# False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'example', False)))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'somethingelse', False)))
		# Undefined
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterExtensibleMatch('generalizedTimeMatch', 'dc', b'example', False)))
		# Not True = False
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'example', True))))
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'uid', b'foobar', True)))) # also matches regular attributes
		# Not False = True
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'example', False))))
		self.assertTrue(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'somethingelse', False))))
		# Not Undefined = Undefined
		self.assertFalse(obj.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('generalizedTimeMatch', 'dc', b'example', False))))

	def test_search(self):
		class TrueEntry(ObjectEntry):
			def match_search(self, base_obj, scope, filter_obj):
				return True

		class FalseEntry(ObjectEntry):
			def match_search(self, base_obj, scope, filter_obj):
				return False

		obj = FalseEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'bar'], uid=[], objectclass=['top'], subschemaSubentry=[DN(schema, 'cn=subschema')])
		self.assertIsNone(obj.search('cn=foo,dc=example,dc=com', ldap.SearchScope.baseObject, ldap.FilterPresent('objectclass'), [], False))
		obj = TrueEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'bar'], uid=[], objectclass=['top'], subschemaSubentry=[DN(schema, 'cn=subschema')])
		result = obj.search('cn=foo,dc=example,dc=com', ldap.SearchScope.baseObject, ldap.FilterPresent('objectclass'), [], False)
		self.assertEqual(result.objectName, 'cn=foo,dc=example,dc=com')
		self.assertEqual(len(result.attributes), 2)
		self.assertEqual({item.type: item.vals for item in result.attributes},
		                 {'cn': [b'foo', b'bar'], 'objectClass': [b'top']})
		result = obj.search('cn=foo,dc=example,dc=com', ldap.SearchScope.baseObject, ldap.FilterPresent('objectclass'), ['*'], False)
		self.assertEqual(result.objectName, 'cn=foo,dc=example,dc=com')
		self.assertEqual(len(result.attributes), 2)
		self.assertEqual({item.type: item.vals for item in result.attributes},
		                 {'cn': [b'foo', b'bar'], 'objectClass': [b'top']})
		result = obj.search('cn=foo,dc=example,dc=com', ldap.SearchScope.baseObject, ldap.FilterPresent('objectclass'), ['+'], False)
		self.assertEqual(result.objectName, 'cn=foo,dc=example,dc=com')
		self.assertEqual(len(result.attributes), 1)
		self.assertEqual({item.type: item.vals for item in result.attributes},
		                 {'subschemaSubentry': [b'cn=subschema']})
		result = obj.search('cn=foo,dc=example,dc=com', ldap.SearchScope.baseObject, ldap.FilterPresent('objectclass'), ['1.1'], False)
		self.assertEqual(result.objectName, 'cn=foo,dc=example,dc=com')
		self.assertEqual(len(result.attributes), 0)
		result = obj.search('cn=foo,dc=example,dc=com', ldap.SearchScope.baseObject, ldap.FilterPresent('objectclass'), ['cn', 'subschemaSubentry', 'foobar'], False)
		self.assertEqual(result.objectName, 'cn=foo,dc=example,dc=com')
		self.assertEqual(len(result.attributes), 2)
		self.assertEqual({item.type: item.vals for item in result.attributes},
		                 {'cn': [b'foo', b'bar'], 'subschemaSubentry': [b'cn=subschema']})
		result = obj.search('cn=foo,dc=example,dc=com', ldap.SearchScope.baseObject, ldap.FilterPresent('objectclass'), ['cn', 'uid', 'subschemaSubentry', 'foobar'], True)
		self.assertEqual(result.objectName, 'cn=foo,dc=example,dc=com')
		self.assertEqual(len(result.attributes), 2)
		self.assertEqual({item.type: item.vals for item in result.attributes},
		                 {'cn': [], 'subschemaSubentry': []})

	def test_compare(self):
		obj = ObjectEntry(schema, 'cn=foo,dc=example,dc=com', cn=['foo', 'bar'], uid=[], objectclass=['top'])
		self.assertTrue(obj.compare('cn=foo,dc=example,dc=com', 'cn', b'bar'))
		self.assertFalse(obj.compare('cn=foo,dc=example,dc=com', 'cn', b'test'))
		with self.assertRaises(ldapserver.exceptions.LDAPUndefinedAttributeType):
			obj.compare('cn=foo,dc=example,dc=com', 'foobar', b'test')
		with self.assertRaises(ldapserver.exceptions.LDAPNoSuchObject):
			obj.compare('cn=bar,dc=example,dc=com', 'cn', b'test')
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			obj.compare('cn=foo,dc=example,dc=com', 'objectclass', b'undefined')

class TestRootDSE(unittest.TestCase):
	def test_init(self):
		obj = RootDSE(schema)
		self.assertEqual(obj.dn, DN(schema))
		obj = RootDSE(schema, cn=['foo', 'bar'])
		self.assertEqual(obj.dn, DN(schema))
		self.assertEqual(obj['cn'], ['foo', 'bar'])

	def test_match_search(self):
		obj = RootDSE(schema, cn=['foo', 'bar'], objectclass=['top'])
		self.assertTrue(obj.match_search('', ldap.SearchScope.baseObject, ldap.FilterPresent('objectclass')))
		self.assertFalse(obj.match_search('cn=root', ldap.SearchScope.baseObject, ldap.FilterPresent('objectclass')))
		self.assertFalse(obj.match_search('', ldap.SearchScope.singleLevel, ldap.FilterPresent('objectclass')))
		self.assertFalse(obj.match_search('', ldap.SearchScope.wholeSubtree, ldap.FilterPresent('objectclass')))
		self.assertFalse(obj.match_search('', ldap.SearchScope.baseObject, ldap.FilterPresent('cn')))

class TestEntryTemplate(unittest.TestCase):
	def test_init(self):
		obj = EntryTemplate(schema, 'ou=users,dc=example,dc=com', 'uid', cn=['foo', 'bar'], uid=[])

	def test_match_search_dn(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD)
		true_filter = ldap.FilterPresent('objectClass')

		scope = ldap.SearchScope.baseObject
		self.assertTrue(template.match_search('cn=foo,dc=example,dc=com', scope, true_filter))
		self.assertFalse(template.match_search('dc=example,dc=com', scope, true_filter))
		self.assertFalse(template.match_search('', scope, true_filter))
		self.assertFalse(template.match_search('cn=test,cn=foo,dc=example,dc=com', scope, true_filter))

		scope = ldap.SearchScope.singleLevel
		self.assertFalse(template.match_search('cn=foo,dc=example,dc=com', scope, true_filter))
		self.assertTrue(template.match_search('dc=example,dc=com', scope, true_filter))
		self.assertFalse(template.match_search('', scope, true_filter))
		self.assertFalse(template.match_search('cn=test,cn=foo,dc=example,dc=com', scope, true_filter))

		scope = ldap.SearchScope.wholeSubtree
		self.assertTrue(template.match_search('cn=foo,dc=example,dc=com', scope, true_filter))
		self.assertTrue(template.match_search('dc=example,dc=com', scope, true_filter))
		self.assertTrue(template.match_search('', scope, true_filter))
		self.assertFalse(template.match_search('cn=test,cn=foo,dc=example,dc=com', scope, true_filter))

	def test_match_search_filter_present(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD)
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		# True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterPresent('objectclass')))
		# False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterPresent('uid')))
		# Undefined (behaves like False)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterPresent('undefined')))
		# Maybe (behaves like True)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterPresent('cn')))
		# We verify in ..._filter_not that Undefined/Maybe are not just False/True

	def test_match_search_filter_not(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD)
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		# Not True = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterPresent('objectclass'))))
		# Not False = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterPresent('uid'))))
		# Not Undefined = Undefined (behaves like False)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterPresent('undefined'))))
		# Not Maybe = Maybe (behaves like True)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterPresent('cn'))))

	def test_match_search_filter_and(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD)
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		true = ldap.FilterPresent('objectclass')
		false = ldap.FilterPresent('uid')
		undefined = ldap.FilterPresent('undefined')
		maybe = ldap.FilterPresent('cn')

		# True = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterAnd([true])))
		# True and True = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterAnd([true, true])))
		# True and False = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterAnd([true, false])))
		# False and False = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterAnd([false, false])))
		# False and Undefined = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterAnd([false, undefined])))
		# True and Undefined = Undefined (behaves like False)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterAnd([true, undefined])))
		# False and Maybe = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterAnd([false, maybe])))
		# True and Maybe = Maybe (behaves like True)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterAnd([true, maybe])))
		# Undefined and Maybe = Undefined (behaves like False)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterAnd([undefined, maybe])))
		# Empty And = True (RFC4526)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterAnd([])))

		# Not True = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([true]))))
		# Not (True and True) = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([true, true]))))
		# Not (True and False) = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([true, false]))))
		# Not (False and False) = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([false, false]))))
		# Not (False and Undefined) = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([false, undefined]))))
		# Not (True and Undefined) = Undefined (behaves like False)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([true, undefined]))))
		# Not (False and Maybe) = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([false, maybe]))))
		# Not (True and Maybe) = Maybe (behaves like True)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([true, maybe]))))
		# Not (Undefined and Maybe) = Undefined (behaves like False)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([undefined, maybe]))))
		# Not (Empty And) = False (RFC4526)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterAnd([]))))

	def test_match_search_filter_or(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD)
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		true = ldap.FilterPresent('objectclass')
		false = ldap.FilterPresent('uid')
		undefined = ldap.FilterPresent('undefined')
		maybe = ldap.FilterPresent('cn')

		# True = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterOr([true])))
		# True or True = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterOr([true, true])))
		# True or False = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterOr([true, false])))
		# False or False = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterOr([false, false])))
		# True or Undefined = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterOr([true, undefined])))
		# False or Undefined = Undefined (behaves like False)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterOr([false, undefined])))
		# True or Maybe = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterOr([true, maybe])))
		# False or Maybe = Maybe (behaves like True)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterOr([false, maybe])))
		# Undefined or Maybe = Maybe (behaves like True)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterOr([undefined, maybe])))
		# Empty Or = False (RFC4526)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterOr([])))

		# Not True = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([true]))))
		# Not (True or True) = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([true, true]))))
		# Not (True or False) = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([true, false]))))
		# Not (False or False) = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([false, false]))))
		# Not (True or Undefined) = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([true, undefined]))))
		# Not (False or Undefined) = Undefined (behaves like False)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([false, undefined]))))
		# Not (True or Maybe) = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([true, maybe]))))
		# Not (False or Maybe) = Maybe (behaves like True)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([false, maybe]))))
		# Not (Undefined or Maybe) = Maybe (behaves like True)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([undefined, maybe]))))
		# Not (Empty Or) = True (RFC4526)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterOr([]))))

	def test_match_search_filter_equal(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD)
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		# True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterEqual('ObjectClass', b'top')))
		# False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterEqual('ObjectClass', b'Person')))
		# Undefined (behaves like False)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterEqual('undefined', b'foo')))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterEqual('telexNumber', b'foo'))) # no EQUALITY
		# Maybe (behaves like True)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterEqual('cn', b'foo')))
		self.assertTrue(template.match_search(dn, scope, ldap.FilterEqual('2.5.4.3', b'Foo'))) # OID
		self.assertTrue(template.match_search(dn, scope, ldap.FilterEqual('name', b'bar'))) # subtype
		# Not True = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('ObjectClass', b'top'))))
		# Not False = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('ObjectClass', b'Person'))))
		# Not Undefined = Undefined (behaves like False)
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('undefined', b'foo'))))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('telexNumber', b'foo')))) # no EQUALITY
		# Not Maybe = Maybe (behaves like True)
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('cn', b'Foo'))))
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('2.5.4.3', b'Foo')))) # OID
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterEqual('name', b'bar')))) # subtype

	def test_match_search_filter_substr(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD, uid=['foobar', 'test'])
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		# True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterSubstrings('uid', [ldap.InitialSubstring(b'foo')])))
		# False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterSubstrings('uid', [ldap.InitialSubstring(b'bar')])))
		# Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterSubstrings('objectclass', [ldap.InitialSubstring(b'foo')])))
		# Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterSubstrings('cn', [ldap.InitialSubstring(b'foo')])))
		# Not True = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterSubstrings('uid', [ldap.InitialSubstring(b'foo')]))))
		# Not False = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterSubstrings('uid', [ldap.InitialSubstring(b'bar')]))))
		# Not Undefined = Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterSubstrings('objectclass', [ldap.InitialSubstring(b'foo')]))))
		# Not Maybe = Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterSubstrings('cn', [ldap.InitialSubstring(b'foo')]))))

	def test_match_search_filter_le(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD, createTimestamp=[datetime.datetime(1994, 12, 16, 10, 32, tzinfo=datetime.timezone.utc)], modifyTimestamp=WILDCARD)
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		# True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterLessOrEqual('createTimestamp', b'199412161032Z')))
		self.assertTrue(template.match_search(dn, scope, ldap.FilterLessOrEqual('createTimestamp', b'199412161033Z')))
		self.assertTrue(template.match_search(dn, scope, ldap.FilterLessOrEqual('objectclass', b'top'))) # LessOrEqual is hybrid between EQUALITY and ORDERING
		# False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterLessOrEqual('createTimestamp', b'199412161031Z')))
		# Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterLessOrEqual('createTimestamp', b'invalid-date')))
		# Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterLessOrEqual('modifyTimestamp', b'199412161032Z')))
		# Not True = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterLessOrEqual('createTimestamp', b'199412161032Z'))))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterLessOrEqual('createTimestamp', b'199412161033Z'))))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterLessOrEqual('objectclass', b'top')))) # LessOrEqual is hybrid between EQUALITY and ORDERING
		# Not False = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterLessOrEqual('createTimestamp', b'199412161031Z'))))
		# Not Undefined = Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterLessOrEqual('createTimestamp', b'invalid-date'))))
		# Not Maybe = Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterLessOrEqual('modifyTimestamp', b'199412161032Z'))))

	def test_match_search_filter_ge(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD, createTimestamp=[datetime.datetime(1994, 12, 16, 10, 32, tzinfo=datetime.timezone.utc)], modifyTimestamp=WILDCARD)
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		# True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterGreaterOrEqual('createTimestamp', b'199412161032Z')))
		self.assertTrue(template.match_search(dn, scope, ldap.FilterGreaterOrEqual('createTimestamp', b'199412161031Z')))
		# False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterGreaterOrEqual('createTimestamp', b'199412161033Z')))
		# Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterGreaterOrEqual('createTimestamp', b'invalid-date')))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterGreaterOrEqual('objectclass', b'top'))) # GreaterOrEqual is only ORDERING
		# Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterGreaterOrEqual('modifyTimestamp', b'199412161032Z')))
		# Not True = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterGreaterOrEqual('createTimestamp', b'199412161032Z'))))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterGreaterOrEqual('createTimestamp', b'199412161031Z'))))
		# Not False = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterGreaterOrEqual('createTimestamp', b'199412161033Z'))))
		# Not Undefined = Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterGreaterOrEqual('createTimestamp', b'invalid-date'))))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterGreaterOrEqual('objectclass', b'top')))) # GreaterOrEqual is only ORDERING
		# Not Maybe = Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterGreaterOrEqual('modifyTimestamp', b'199412161032Z'))))

	def test_match_search_filter_extensible_attribute_type(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD, uid=['foobar'])
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		# True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterExtensibleMatch(None, 'uid', b'Foobar', False)))
		self.assertTrue(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'uid', b'Foobar', False)))
		self.assertTrue(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreSubstringsMatch', 'uid', b'F*b*r', False)))
		# False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseExactMatch', 'uid', b'Foobar', False)))
		# Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseExactMatch', 'createTimestamp', b'199412161032Z', False)))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterExtensibleMatch('generalizedTimeMatch', 'cn', b'199412161032Z', False)))
		# Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'cn', b'Foobar', False)))
		# Not True = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch(None, 'uid', b'Foobar', False))))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'uid', b'Foobar', False))))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreSubstringsMatch', 'uid', b'F*b*r', False))))
		# Not False = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseExactMatch', 'uid', b'Foobar', False))))
		# Not Undefined = Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseExactMatch', 'createTimestamp', b'199412161032Z', False))))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('generalizedTimeMatch', 'cn', b'199412161032Z', False))))
		# Not Maybe = Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'cn', b'Foobar', False))))

	def test_match_search_filter_extensible_no_attribute_type(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD, uid=['foobar'])
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		# True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', None, b'foobar', False)))
		self.assertTrue(template.match_search(dn, scope, ldap.FilterExtensibleMatch('objectIdentifierMatch', None, b'top', False)))
		# False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterExtensibleMatch('objectIdentifierMatch', None, b'person', False)))
		# Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterExtensibleMatch('octetStringOrderingMatch', None, b'someoctetstring', False)))
		# Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', None, b'foo', False)))
		# Not True = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', None, b'foobar', False))))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('objectIdentifierMatch', None, b'top', False))))
		# Not False = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('objectIdentifierMatch', None, b'person', False))))
		# Not Undefined = Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('octetStringOrderingMatch', None, b'someoctetstring', False))))
		# Not Maybe = Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', None, b'foo', False))))

	def test_match_search_filter_extensible_dn(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD, uid=['foobar'])
		dn = 'dc=example,dc=com'
		scope = ldap.SearchScope.wholeSubtree
		# True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'example', True)))
		self.assertTrue(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'uid', b'foobar', True))) # also matches regular attributes
		# False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'example', False)))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'somethingelse', False)))
		# Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterExtensibleMatch('generalizedTimeMatch', 'dc', b'example', False)))
		# Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterExtensibleMatch('caseIgnoreMatch', 'cn', b'foo', True)))
		# Not True = False
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'example', True))))
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'uid', b'foobar', True)))) # also matches regular attributes
		# Not False = True
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'example', False))))
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'dc', b'somethingelse', False))))
		# Not Undefined = Undefined
		self.assertFalse(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('generalizedTimeMatch', 'dc', b'example', False))))
		# Not Maybe = Maybe
		self.assertTrue(template.match_search(dn, scope, ldap.FilterNot(ldap.FilterExtensibleMatch('caseIgnoreMatch', 'cn', b'foo', True))))

	def test_extract_search_constraints(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD, uid=['foobar'])
		self.assertEqual(dict(template.extract_search_constraints('dc=exapmle,dc=com', ldap.SearchScope.wholeSubtree, ldap.FilterEqual('cn', b'foo')).items()), {'cn': ['foo']})
		self.assertEqual(dict(template.extract_search_constraints('dc=exapmle,dc=com', ldap.SearchScope.wholeSubtree, ldap.FilterAnd([ldap.FilterEqual('objectclass', b'top'), ldap.FilterEqual('cn', b'foo')])).items()), {'cn': ['foo'], 'objectClass': ['top']})
		self.assertEqual(dict(template.extract_search_constraints('dc=exapmle,dc=com', ldap.SearchScope.wholeSubtree, ldap.FilterOr([ldap.FilterEqual('cn', b'foo')])).items()), {'cn': ['foo']})
		self.assertEqual(dict(template.extract_search_constraints('cn=foo,dc=example,dc=com', ldap.SearchScope.baseObject, ldap.FilterPresent('objectClass')).items()), {'cn': ['foo']})
		self.assertEqual(dict(template.extract_search_constraints('dc=example,dc=com', ldap.SearchScope.baseObject, ldap.FilterPresent('objectClass')).items()), {})

	def test_create_entry(self):
		template = EntryTemplate(schema, 'dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD, c=WILDCARD, uid=['foobar'])
		obj = template.create_entry('foo', cn=['foo', 'bar'], c=['DE'])
		self.assertEqual(obj.dn, DN(schema, 'cn=foo,dc=example,dc=com'))
		self.assertEqual(dict(obj.items()), {'cn': ['foo', 'bar'], 'uid': ['foobar'], 'c': ['DE'], 'objectClass': ['top']})
		obj = template.create_entry('foo', cn=['foo', 'bar'])
		self.assertEqual(dict(obj.items()), {'cn': ['foo', 'bar'], 'uid': ['foobar'], 'objectClass': ['top']})
		with self.assertRaises(ValueError):
			template.create_entry('foo', cn=['foo', 'bar'], c=['DE'], description=['foo bar'])

class TestSubschemaSubentry(unittest.TestCase):
	def test_init(self):
		obj = SubschemaSubentry(schema, 'cn=Subschema', cn=['Subschema'])
		self.assertIn('subschema', obj['objectClass'])

	def test_match_search(self):
		obj = SubschemaSubentry(schema, 'cn=Subschema', cn=['Subschema'])
		self.assertIn("( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )", [str(item) for item in obj['objectClasses']])
		self.assertIn("( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )", [str(item) for item in obj['ldapSyntaxes']])
		self.assertIn("( 2.5.13.5 NAME 'caseExactMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", [str(item) for item in obj['matchingRules']])
		self.assertIn("( 2.5.21.6 NAME 'objectClasses' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )", [str(item) for item in obj['attributeTypes']])
		[str(item) for item in obj['matchingRuleUse']]

	def test_constructors(self):
		subschema = SubschemaSubentry(schema, 'cn=Subschema', cn=['Subschema'])
		attrs = subschema.AttributeDict(cn=['foo'])
		self.assertIsInstance(attrs, AttributeDict)
		self.assertIs(attrs.schema, subschema.schema)
		self.assertEqual(attrs['cn'], ['foo'])
		obj = subschema.ObjectEntry('cn=foo,dc=example,dc=com', cn=['foo'])
		self.assertIsInstance(obj, ObjectEntry)
		self.assertIs(obj.schema, subschema.schema)
		self.assertEqual(obj.dn, DN(schema, 'cn=foo,dc=example,dc=com'))
		self.assertEqual(obj['cn'], ['foo'])
		self.assertEqual(obj['subschemaSubentry'], [DN(schema, 'cn=Subschema')])
		rootdse = subschema.RootDSE(cn=['foo'])
		self.assertIsInstance(rootdse, RootDSE)
		self.assertIs(rootdse.schema, subschema.schema)
		self.assertEqual(rootdse['cn'], ['foo'])
		template = subschema.EntryTemplate('dc=example,dc=com', 'cn', objectclass=['top'], cn=WILDCARD)
		self.assertIsInstance(template, EntryTemplate)
		self.assertIs(template.schema, subschema.schema)
		self.assertEqual(template['subschemaSubentry'], [DN(schema, 'cn=Subschema')])
