import unittest
import enum

from ldapserver import asn1

class TestOctetString(unittest.TestCase):
	def test_from_ber(self):
		self.assertEqual(asn1.OctetString.from_ber(b'\x04\x00'), (b'', b''))
		self.assertEqual(asn1.OctetString.from_ber(b'\x04\x03foo'), (b'foo', b''))

	def test_to_ber(self):
		self.assertEqual(asn1.OctetString.to_ber(b''), b'\x04\x00')
		self.assertEqual(asn1.OctetString.to_ber(b'foo'), b'\x04\x03foo')

class TestInteger(unittest.TestCase):
	def test_from_ber(self):
		self.assertEqual(asn1.Integer.from_ber(b'\x02\x01\x00'), (0, b''))
		self.assertEqual(asn1.Integer.from_ber(b'\x02\x01\x01'), (1, b''))
		self.assertEqual(asn1.Integer.from_ber(b'\x02\x01\x7f'), (127, b''))
		self.assertEqual(asn1.Integer.from_ber(b'\x02\x02\x00\x80'), (128, b''))
		self.assertEqual(asn1.Integer.from_ber(b'\x02\x02\x01\x00'), (256, b''))
		self.assertEqual(asn1.Integer.from_ber(b'\x02\x01\xff'), (-1, b''))
		self.assertEqual(asn1.Integer.from_ber(b'\x02\x01\x80'), (-128, b''))
		self.assertEqual(asn1.Integer.from_ber(b'\x02\x02\xff\x7f'), (-129, b''))

	def test_to_ber(self):
		self.assertEqual(asn1.Integer.to_ber(0), b'\x02\x01\x00')
		self.assertEqual(asn1.Integer.to_ber(1), b'\x02\x01\x01')
		self.assertEqual(asn1.Integer.to_ber(127), b'\x02\x01\x7f')
		self.assertEqual(asn1.Integer.to_ber(128), b'\x02\x02\x00\x80')
		self.assertEqual(asn1.Integer.to_ber(256), b'\x02\x02\x01\x00')
		self.assertEqual(asn1.Integer.to_ber(-1), b'\x02\x01\xff')
		self.assertEqual(asn1.Integer.to_ber(-128), b'\x02\x01\x80')
		self.assertEqual(asn1.Integer.to_ber(-129), b'\x02\x02\xff\x7f')

class TestBoolean(unittest.TestCase):
	def test_from_ber(self):
		self.assertEqual(asn1.Boolean.from_ber(b'\x01\x01\xff'), (True, b''))
		self.assertEqual(asn1.Boolean.from_ber(b'\x01\x01\x00'), (False, b''))

	def test_to_ber(self):
		self.assertEqual(asn1.Boolean.to_ber(True), b'\x01\x01\xff')
		self.assertEqual(asn1.Boolean.to_ber(False), b'\x01\x01\x00')

class TestEnum(unittest.TestCase):
	def test_from_ber(self):
		class CustomEnum(enum.Enum):
			NULL = 0
			ONE = 1
		self.assertEqual(asn1.wrapenum(CustomEnum).from_ber(b'\x0a\x01\x00'), (CustomEnum.NULL, b''))
		self.assertEqual(asn1.wrapenum(CustomEnum).from_ber(b'\x0a\x01\x01'), (CustomEnum.ONE, b''))

	def test_to_ber(self):
		class CustomEnum(enum.Enum):
			NULL = 0
			ONE = 1
		self.assertEqual(asn1.wrapenum(CustomEnum).to_ber(CustomEnum.NULL), b'\x0a\x01\x00')
		self.assertEqual(asn1.wrapenum(CustomEnum).to_ber(CustomEnum.ONE), b'\x0a\x01\x01')
