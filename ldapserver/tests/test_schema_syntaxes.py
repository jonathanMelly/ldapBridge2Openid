import unittest
import datetime

import ldapserver
from ldapserver.schema import syntaxes

schema = ldapserver.schema.RFC4519_SCHEMA

class TestBytesSyntaxDefinition(unittest.TestCase):
	def test_encode(self):
		syntax = syntaxes.OctetString
		self.assertEqual(syntax.encode(schema, b'Foo'), b'Foo')

	def test_decode(self):
		syntax = syntaxes.OctetString
		self.assertEqual(syntax.decode(schema, b'Foo'), b'Foo')

class TestStringSyntaxDefinition(unittest.TestCase):
	def test_encode(self):
		syntax = syntaxes.DirectoryString
		self.assertEqual(syntax.encode(schema, 'Foo'), b'Foo')
		self.assertEqual(syntax.encode(schema, 'äöü'), b'\xc3\xa4\xc3\xb6\xc3\xbc')

	def test_decode(self):
		syntax = syntaxes.DirectoryString
		self.assertEqual(syntax.decode(schema, b'Foo'), 'Foo')
		self.assertEqual(syntax.decode(schema, b'\xc3\xa4\xc3\xb6\xc3\xbc'), 'äöü')
		syntax = syntaxes.IA5String
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b'\xc3\xa4\xc3\xb6\xc3\xbc')
		# Test regex matching
		syntax = syntaxes.BitString
		self.assertEqual(syntax.decode(schema, b"''B"), "''B")
		self.assertEqual(syntax.decode(schema, b"'0'B"), "'0'B")
		self.assertEqual(syntax.decode(schema, b"'010101'B"), "'010101'B")
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b"")
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b"'0'")
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b"'0'b")
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b"'0123'B")

class TestIntegerSyntaxDefinition(unittest.TestCase):
	def test_encode(self):
		syntax = syntaxes.INTEGER
		self.assertEqual(syntax.encode(schema, 0), b'0')
		self.assertEqual(syntax.encode(schema, 1234), b'1234')
		self.assertEqual(syntax.encode(schema, -1234), b'-1234')

	def test_decode(self):
		syntax = syntaxes.INTEGER
		self.assertEqual(syntax.decode(schema, b'0'), 0)
		self.assertEqual(syntax.decode(schema, b'1234'), 1234)
		self.assertEqual(syntax.decode(schema, b'-1234'), -1234)
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b'-0')
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b'+1')
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b'0123')

class TestSchemaElementSyntaxDefinition(unittest.TestCase):
	def test_encode(self):
		class SchemaElement:
			def __str__(self):
				return '( SCHEMA ELEMENT )'
		syntax = syntaxes.SchemaElementSyntaxDefinition('1.2.3.4')
		self.assertEqual(syntax.encode(schema, SchemaElement()), b'( SCHEMA ELEMENT )')

class TestBooleanSyntaxDefinition(unittest.TestCase):
	def test_encode(self):
		syntax = syntaxes.Boolean
		self.assertEqual(syntax.encode(schema, True), b'TRUE')
		self.assertEqual(syntax.encode(schema, False), b'FALSE')

	def test_decode(self):
		syntax = syntaxes.Boolean
		self.assertEqual(syntax.decode(schema, b'TRUE'), True)
		self.assertEqual(syntax.decode(schema, b'FALSE'), False)
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b'true')
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b'')

class TestDNSyntaxDefinition(unittest.TestCase):
	def test_encode(self):
		syntax = syntaxes.DN
		self.assertEqual(syntax.encode(schema, ldapserver.dn.DN(schema, cn='foobar')), b'cn=foobar')

	def test_decode(self):
		syntax = syntaxes.DN
		self.assertEqual(syntax.decode(schema, b'cn=foobar'), ldapserver.dn.DN(schema, cn='foobar'))
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b'cn=foobar,,,')

class TestNameAndOptionalUIDSyntaxDefinition(unittest.TestCase):
	def test_encode(self):
		syntax = syntaxes.NameAndOptionalUID
		self.assertEqual(syntax.encode(schema, ldapserver.dn.DN(schema, cn='foobar')), b'cn=foobar')
		self.assertEqual(syntax.encode(schema, ldapserver.dn.DNWithUID(schema, ldapserver.dn.DN(schema, cn='foobar'), "'0101'B")), b"cn=foobar#'0101'B")

	def test_decode(self):
		syntax = syntaxes.NameAndOptionalUID
		self.assertEqual(syntax.decode(schema, b'cn=foobar'), ldapserver.dn.DN(schema, cn='foobar'))
		self.assertEqual(syntax.decode(schema, b"cn=foobar#'0101'B"), ldapserver.dn.DNWithUID(schema, ldapserver.dn.DN(schema, cn='foobar'), "'0101'B"))
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b'cn=foobar,,,')
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b"cn=foobar,,,#'0101'B")
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b"cn=foobar#'0102'B")

class TestGeneralizedTimeSyntaxDefinition(unittest.TestCase):
	def test_encode(self):
		syntax = syntaxes.GeneralizedTime
		self.assertEqual(syntax.encode(schema, datetime.datetime(1994, 12, 16, 10, 32, tzinfo=datetime.timezone.utc)),
		                 b'199412161032Z')
		self.assertEqual(syntax.encode(schema, datetime.datetime(1994, 12, 16, 5, 32, tzinfo=datetime.timezone(datetime.timedelta(hours=-5)))),
		                 b'199412160532-0500')

	def test_decode(self):
		syntax = syntaxes.GeneralizedTime
		self.assertEqual(syntax.decode(schema, b'199412161032Z'),
		                 datetime.datetime(1994, 12, 16, 10, 32, tzinfo=datetime.timezone.utc))
		self.assertEqual(syntax.decode(schema, b'199412160532-0500'),
		                 datetime.datetime(1994, 12, 16, 5, 32, tzinfo=datetime.timezone(datetime.timedelta(hours=-5))))

class TestPostalAddressSyntaxDefinition(unittest.TestCase):
	def test_encode(self):
		syntax = syntaxes.PostalAddress
		self.assertEqual(syntax.encode(schema, ['1234 Main St.', 'Anytown, CA 12345', 'USA']),
		                 b'1234 Main St.$Anytown, CA 12345$USA')
		self.assertEqual(syntax.encode(schema, ['$1,000,000 Sweepstakes', 'PO Box 1000000', 'Anytown, CA 12345', 'USA']),
		                 b'\\241,000,000 Sweepstakes$PO Box 1000000$Anytown, CA 12345$USA')

	def test_decode(self):
		syntax = syntaxes.PostalAddress
		self.assertEqual(syntax.decode(schema, b'1234 Main St.$Anytown, CA 12345$USA'),
		                 ['1234 Main St.', 'Anytown, CA 12345', 'USA'])
		self.assertEqual(syntax.decode(schema, b'\\241,000,000 Sweepstakes$PO Box 1000000$Anytown, CA 12345$USA'),
		                 ['$1,000,000 Sweepstakes', 'PO Box 1000000', 'Anytown, CA 12345', 'USA'])

class TestSubstringAssertionSyntaxDefinition(unittest.TestCase):
	def test_decode(self):
		syntax = syntaxes.SubstringAssertion
		self.assertEqual(syntax.decode(schema, b'*foo*'), (None, ['foo'], None))
		self.assertEqual(syntax.decode(schema, b'*foo*bar*'), (None, ['foo', 'bar'], None))
		self.assertEqual(syntax.decode(schema, b'a*foo*bar*b'), ('a', ['foo', 'bar'], 'b'))
		self.assertEqual(syntax.decode(schema, b'a*b'), ('a', [], 'b'))
		self.assertEqual(syntax.decode(schema, b' a\\2A*\\2Afoo*\\5Cbar*\\2Ab'), (' a*', ['*foo', '\\bar'], '*b'))
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b'')
		with self.assertRaises(ldapserver.exceptions.LDAPInvalidAttributeSyntax):
			syntax.decode(schema, b'foo')

class TestUTCTimeSyntaxDefinition(unittest.TestCase):
	def test_encode(self):
		syntax = syntaxes.UTCTime
		self.assertEqual(syntax.encode(schema, datetime.datetime(1994, 12, 16, 10, 32, tzinfo=datetime.timezone.utc)),
		                 b'9412161032Z')
		self.assertEqual(syntax.encode(schema, datetime.datetime(1994, 12, 16, 5, 32, tzinfo=datetime.timezone(datetime.timedelta(hours=-5)))),
		                 b'9412160532-0500')

	def test_decode(self):
		syntax = syntaxes.UTCTime
		self.assertEqual(syntax.decode(schema, b'9412161032Z'),
		                 datetime.datetime(1994, 12, 16, 10, 32, tzinfo=datetime.timezone.utc))
		self.assertEqual(syntax.decode(schema, b'9412160532-0500'),
		                 datetime.datetime(1994, 12, 16, 5, 32, tzinfo=datetime.timezone(datetime.timedelta(hours=-5))))


