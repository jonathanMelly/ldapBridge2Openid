import unittest
import enum

from ldapserver.dn import DN, RDN, RDNAssertion
from ldapserver.schema import RFC4519_SCHEMA as schema

class Wrapper:
	def __init__(self, cls, schema):
		self.cls = cls
		self.schema = schema

	def __call__(self, *args, **kwargs):
		return self.cls(self.schema, *args, **kwargs)

	def from_str(self, *args, **kwargs):
		return self.cls.from_str(self.schema, *args, **kwargs)

DN = Wrapper(DN, schema)
RDN = Wrapper(RDN, schema)
RDNAssertion = Wrapper(RDNAssertion, schema)

class TestDN(unittest.TestCase):
	def test_equal(self):
		self.assertEqual(DN(), DN())
		self.assertEqual(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')), DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))
		self.assertNotEqual(DN(RDN(dc='example'), RDN(dc='net')), DN(RDN(dc='net'), RDN(dc='example')))

	def test_repr(self):
		repr(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))
		repr(DN(RDN(cn='James "Jim" Smith, III'), RDN(dc='example'), RDN(dc='net')))

	def test_init(self):
		self.assertEqual(DN(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net'))), DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN(r'uid=jsmith,dc=example,dc=net'), DN.from_str(r'uid=jsmith,dc=example,dc=net'))
		self.assertEqual(DN(uid='jsmith'), DN(RDN(uid='jsmith')))
		self.assertEqual(DN(ou='Sales', cn='J.  Smith'), DN(RDN(ou='Sales', cn='J.  Smith')))
		self.assertEqual(DN(RDN(dc='example'), RDN(dc='net'), uid='jsmith'), DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN(r'dc=example,dc=net', uid='jsmith'), DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))

	def test_is_direct_child_of(self):
		self.assertTrue(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')).is_direct_child_of(DN(RDN(dc='example'), RDN(dc='net'))))
		self.assertFalse(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')).is_direct_child_of(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net'))))
		self.assertFalse(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')).is_direct_child_of(DN(RDN(dc='foobar'), RDN(dc='net'))))
		self.assertFalse(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')).is_direct_child_of(DN(RDN(dc='net'))))
		self.assertFalse(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')).is_direct_child_of(DN(RDN(cn='foobar'), RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net'))))
		self.assertFalse(DN().is_direct_child_of(DN()))
		self.assertTrue(DN(RDN(cn='Subschema')).is_direct_child_of(DN()))

	def test_in_subtree_of(self):
		self.assertTrue(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')).in_subtree_of(DN(RDN(dc='example'), RDN(dc='net'))))
		self.assertTrue(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')).in_subtree_of(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net'))))
		self.assertFalse(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')).in_subtree_of(DN(RDN(dc='foobar'), RDN(dc='net'))))
		self.assertTrue(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')).in_subtree_of(DN(RDN(dc='net'))))
		self.assertFalse(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')).in_subtree_of(DN(RDN(cn='foobar'), RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net'))))
		self.assertTrue(DN().in_subtree_of(DN()))
		self.assertTrue(DN(RDN(cn='Subschema')).in_subtree_of(DN()))

	def test_add(self):	
		self.assertEqual(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')) + DN(), DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN() + DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')), DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN(RDN(uid='jsmith'), RDN(dc='example')) + RDN(dc='net'), DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN(RDN(uid='jsmith')) + DN(RDN(dc='example') + RDN(dc='net')), DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))

	def test_encode(self):
		self.assertEqual(str(DN()), r'')
		self.assertIn(str(DN(RDN(uid='j,smith'), RDN(dc='example'), RDN(dc='net'))), [r'uid=j\,smith,dc=example,dc=net', r'uid=j\2csmith,dc=example,dc=net'])
		# Examples from RFC4514
		self.assertEqual(str(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net'))), r'uid=jsmith,dc=example,dc=net')
		self.assertIn(str(DN(RDN(ou='Sales', cn='J.  Smith'), RDN(dc='example'), RDN(dc='net'))), [r'ou=Sales+cn=J.  Smith,dc=example,dc=net',
		                                                                                           r'cn=J.  Smith+ou=Sales,dc=example,dc=net'])
		self.assertIn(str(DN(RDN(cn='James "Jim" Smith, III'), RDN(dc='example'), RDN(dc='net'))), [r'cn=James \"Jim\" Smith\, III,dc=example,dc=net',
		                                                                                            r'cn=James \22Jim\22 Smith\2c III,dc=example,dc=net'])
		self.assertEqual(str(DN(RDN(cn='Before\rAfter'), RDN(dc='example'), RDN(dc='net'))), r'cn=Before\0dAfter,dc=example,dc=net')
		self.assertIn(str(DN(RDN(cn='Lučić'))), [r'cn=Lučić', r'cn=Lu\c4\8di\c4\87'])

	def test_decode(self):
		self.assertEqual(DN.from_str(r''), DN())
		self.assertEqual(DN.from_str(r'uid=j\,smith,dc=example,dc=net'), DN(RDN(uid='j,smith'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN.from_str(r'uid=j\2csmith,dc=example,dc=net'), DN(RDN(uid='j,smith'), RDN(dc='example'), RDN(dc='net')))
		# Examples from RFC4514
		self.assertEqual(DN.from_str(r'uid=jsmith,dc=example,dc=net'), DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN.from_str(r'ou=Sales+cn=J.  Smith,dc=example,dc=net'), DN(RDN(ou='Sales', cn='J.  Smith'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN.from_str(r'cn=J.  Smith+ou=Sales,dc=example,dc=net'), DN(RDN(ou='Sales', cn='J.  Smith'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN.from_str(r'cn=James \"Jim\" Smith\, III,dc=example,dc=net'), DN(RDN(cn='James "Jim" Smith, III'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN.from_str(r'cn=James \22Jim\22 Smith\2c III,dc=example,dc=net'), DN(RDN(cn='James "Jim" Smith, III'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN.from_str(r'cn=Before\0dAfter,dc=example,dc=net'), DN(RDN(cn='Before\rAfter'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(DN.from_str(r'cn=Lučić'), DN(RDN(cn='Lučić')))
		self.assertEqual(DN.from_str(r'cn=Lu\c4\8di\c4\87'), DN(RDN(cn='Lučić')))
		with self.assertRaises(ValueError):
			DN.from_str(r'invalidAttributeType=foobar,dc=example,dc=net')
		with self.assertRaises(ValueError):
			DN.from_str(r'cn=,dc=example,dc=net')
		with self.assertRaises(ValueError):
			DN.from_str(r',')

	def test_slice(self):
		self.assertEqual(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net'))[1], RDN(dc='example'))
		self.assertEqual(DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net'))[1:], DN(RDN(dc='example'), RDN(dc='net')))

class TestRDN(unittest.TestCase):
	def test_equal(self):
		self.assertEqual(RDN(RDNAssertion('uid', 'jsmith')), RDN(RDNAssertion('uid', 'Jsmith')))
		self.assertEqual(RDN(RDNAssertion('uid', 'jsmith')), RDN(RDNAssertion('UID', 'jsmith')))
		self.assertEqual(RDN(RDNAssertion('ou', 'Sales'), RDNAssertion('cn', 'J.  Smith'), RDNAssertion('ou', 'HR')),
		                 RDN(RDNAssertion('cn', 'J.  Smith'), RDNAssertion('ou', 'HR'), RDNAssertion('ou', 'Sales')))

	def test_repr(self):
		repr(RDN(cn='J.  Smith', ou='Sales'))
		repr(RDN(cn='James "Jim" Smith, III'))

	def test_init(self):
		self.assertEqual(RDN(cn='J.  Smith', ou='Sales'),
		                 RDN(RDNAssertion('cn', 'J.  Smith'), RDNAssertion('ou', 'Sales')))
		self.assertEqual(RDN(RDNAssertion('cn', 'J.  Smith'), RDNAssertion('ou', 'Sales'), ou='HR'),
		                 RDN(RDNAssertion('cn', 'J.  Smith'), RDNAssertion('ou', 'Sales'), RDNAssertion('ou', 'HR')))
		with self.assertRaises(ValueError):
			RDN()

	def test_add(self):	
		self.assertEqual(RDN(uid='jsmith') + DN(RDN(dc='example'), RDN(dc='net')), DN(RDN(uid='jsmith'), RDN(dc='example'), RDN(dc='net')))
		self.assertEqual(RDN(uid='jsmith') + RDN(dc='example'), DN(RDN(uid='jsmith'), RDN(dc='example')))

	def test_encode(self):
		self.assertEqual(str(RDN(cn='foo')), r'cn=foo')
		self.assertIn(str(RDN(cn='foo', ou='bar')), [r'cn=foo+ou=bar', r'ou=bar+cn=foo'])
		self.assertIn(str(RDN(cn='foo+bar', ou='bar')), [r'cn=foo\+bar+ou=bar', r'cn=foo\2bbar+ou=bar',
		                                                 r'ou=bar+cn=foo\+bar', r'ou=bar+cn=foo\2bbar'])
		# Examples from RFC4514
		self.assertIn(str(RDN(ou='Sales', cn='J.  Smith')), [r'ou=Sales+cn=J.  Smith', r'cn=J.  Smith+ou=Sales'])
		self.assertEqual(str(RDN(cn='James "Jim" Smith, III')), r'cn=James \"Jim\" Smith\, III')

	def test_decode(self):
		self.assertEqual(RDN.from_str(r'cn=foo'), RDN(cn='foo'))
		self.assertEqual(RDN.from_str(r'cn=foo+ou=bar'), RDN(cn='foo', ou='bar'))
		self.assertEqual(RDN.from_str(r'cn=foo\+bar+ou=bar'), RDN(cn='foo+bar', ou='bar'))
		# Examples from RFC4514
		self.assertEqual(RDN.from_str(r'OU=Sales+CN=J.  Smith'), RDN(ou='Sales', cn='J.  Smith'))
		self.assertEqual(RDN.from_str(r'CN=James \"Jim\" Smith\, III'), RDN(cn='James "Jim" Smith, III'))
		with self.assertRaises(ValueError):
			RDN.from_str(r'')
		with self.assertRaises(ValueError):
			RDN.from_str(r'cn')
		with self.assertRaises(ValueError):
			RDN.from_str(r'cn=')
		with self.assertRaises(ValueError):
			RDN.from_str(r'cn=foo+ou+dc=bar')

class TestRDNAssertion(unittest.TestCase):
	def test_init(self):
		with self.assertRaises(ValueError):
			RDNAssertion('invalidAttributeType', 'foobar')
		# We currently don't validate values
		#with self.assertRaises(ValueError):
		#	RDNAssertion('cn', '')

	def test_equal(self):
		# NFD vs. NFC of string value
		self.assertEqual(RDNAssertion('cn', b'fooa\xcc\x88bar'.decode()), RDNAssertion('CN', b'foo\xc3\xa4bar'.decode()))
		# Different case of string value
		self.assertEqual(RDNAssertion('cn', 'foo bar'), RDNAssertion('cn', 'Foo Bar'))
		self.assertEqual(RDNAssertion('cn', 'ä'), RDNAssertion('cn', 'Ä'))
		# Different case of type
		self.assertEqual(RDNAssertion('cn', 'foo'), RDNAssertion('CN', 'foo'))

	def test_hash(self):
		# NFD vs. NFC of string value
		self.assertEqual(hash(RDNAssertion('cn', b'fooa\xcc\x88bar'.decode())), hash(RDNAssertion('CN', b'foo\xc3\xa4bar'.decode())))
		# Different case of string value
		self.assertEqual(hash(RDNAssertion('cn', 'foo bar')), hash(RDNAssertion('cn', 'Foo Bar')))
		self.assertEqual(hash(RDNAssertion('cn', 'ä')), hash(RDNAssertion('cn', 'Ä')))
		# Different case of type
		self.assertEqual(hash(RDNAssertion('cn', 'foo')), hash(RDNAssertion('CN', 'foo')))

	def test_repr(self):
		repr(RDNAssertion('cn', 'foobar'))
		repr(RDNAssertion('cn', 'foo\x00bar'))

	def test_immutability(self):
		assertion = RDNAssertion('cn', 'foobar')
		with self.assertRaises(TypeError):
			assertion.attribute = 'uid'
		with self.assertRaises(TypeError):
			assertion.value = 'something'
		with self.assertRaises(TypeError):
			assertion.value_normalized = 'something'
		with self.assertRaises(TypeError):
			del assertion.attribute
		with self.assertRaises(TypeError):
			del assertion.value
		with self.assertRaises(TypeError):
			del assertion.value_normalized

	def test_encode(self):
		self.assertIn(str(RDNAssertion('cn', ' foobar')), [r'cn=\ foobar', r'cn=\20foobar'])
		self.assertIn(str(RDNAssertion('cn', '#foobar')), [r'cn=\#foobar', r'cn=\23foobar'])
		self.assertIn(str(RDNAssertion('cn', 'foobar ')), [r'cn=foobar\ ', r'cn=foobar\20'])
		self.assertIn(str(RDNAssertion('cn', 'foo\\bar')), [r'cn=foo\\bar', r'cn=foo\5cbar'])
		self.assertIn(str(RDNAssertion('cn', 'foo,bar')), [r'cn=foo\,bar', r'cn=foo\2cbar'])
		self.assertIn(str(RDNAssertion('cn', 'foo+bar')), [r'cn=foo\+bar', r'cn=foo\2bbar'])
		self.assertEqual(str(RDNAssertion('cn', 'foo\x00bar')), r'cn=foo\00bar')
		self.assertIn(str(RDNAssertion('cn', 'foo"bar')), [r'cn=foo\"bar', r'cn=foo\22bar'])
		self.assertIn(str(RDNAssertion('cn', 'foo;bar')), [r'cn=foo\;bar', r'cn=foo\3bbar'])
		self.assertIn(str(RDNAssertion('cn', 'foo<bar')), [r'cn=foo\<bar', r'cn=foo\3cbar'])
		self.assertIn(str(RDNAssertion('cn', 'foo>bar')), [r'cn=foo\>bar', r'cn=foo\3ebar'])
		# Examples from RFC4514
		self.assertEqual(str(RDNAssertion('cn', 'Before\rAfter')), r'cn=Before\0dAfter')
		self.assertIn(str(RDNAssertion('cn', 'James "Jim" Smith')), [r'cn=James \"Jim\" Smith', r'cn=James \22Jim\22 Smith'])
		self.assertIn(str(RDNAssertion('cn', 'Lučić')), [r'cn=Lučić', r'cn=Lu\c4\8di\c4\87'])

	def test_decode(self):
		self.assertEqual(RDNAssertion.from_str(r'cn=\ foobar'), RDNAssertion('cn', ' foobar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=\20foobar'), RDNAssertion('cn', ' foobar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=\#foobar'), RDNAssertion('cn', '#foobar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=\23foobar'), RDNAssertion('cn', '#foobar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foobar\ '), RDNAssertion('cn', 'foobar '))
		self.assertEqual(RDNAssertion.from_str(r'cn=foobar\20'), RDNAssertion('cn', 'foobar '))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\\bar'), RDNAssertion('cn', 'foo\\bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\5cbar'), RDNAssertion('cn', 'foo\\bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\,bar'), RDNAssertion('cn', 'foo,bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\2cbar'), RDNAssertion('cn', 'foo,bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\+bar'), RDNAssertion('cn', 'foo+bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\2bbar'), RDNAssertion('cn', 'foo+bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\00bar'), RDNAssertion('cn', 'foo\x00bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\"bar'), RDNAssertion('cn', 'foo"bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\;bar'), RDNAssertion('cn', 'foo;bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\<bar'), RDNAssertion('cn', 'foo<bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\>bar'), RDNAssertion('cn', 'foo>bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\>bar'), RDNAssertion('cn', 'foo>bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo#bar'), RDNAssertion('cn', 'foo#bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\#bar'), RDNAssertion('cn', 'foo#bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo bar'), RDNAssertion('cn', 'foo bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\ bar'), RDNAssertion('cn', 'foo bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo=bar'), RDNAssertion('cn', 'foo=bar'))
		self.assertEqual(RDNAssertion.from_str(r'cn=foo\=bar'), RDNAssertion('cn', 'foo=bar'))
		self.assertEqual(RDNAssertion.from_str(r'CN=Before\0dAfter'), RDNAssertion('cn', 'Before\rAfter'))
		self.assertEqual(RDNAssertion.from_str(r'cn=James \"Jim\" Smith'), RDNAssertion('cn', 'James "Jim" Smith'))
		self.assertEqual(RDNAssertion.from_str(r'cn=James \22Jim\22 Smith'), RDNAssertion('cn', 'James "Jim" Smith'))
		self.assertEqual(RDNAssertion.from_str(r'CN=Lučić'), RDNAssertion('cn', 'Lučić'))
		self.assertEqual(RDNAssertion.from_str(r'CN=Lu\C4\8Di\C4\87'), RDNAssertion('cn', 'Lučić'))
		with self.assertRaises(ValueError):
			RDNAssertion.from_str(r'1.3.6.1.4.1.1466.0=#04024869')
		with self.assertRaises(ValueError):
			RDNAssertion.from_str(r'cn=foo\Xbar')
		with self.assertRaises(ValueError):
			RDNAssertion.from_str(r'invalidAttributeType=test')
		with self.assertRaises(ValueError):
			RDNAssertion.from_str(r'cn=')
		with self.assertRaises(ValueError):
			RDNAssertion.from_str(r'=foo')
		with self.assertRaises(ValueError):
			RDNAssertion.from_str(r'')
		with self.assertRaises(ValueError):
			RDNAssertion.from_str(r'foo')
