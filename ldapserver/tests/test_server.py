import unittest

from ldapserver import BaseLDAPRequestHandler, LDAPRequestHandler, ldap, exceptions

class MockConnection:
	def __init__(self, data, chunksize):
		self.data = data
		self.chunksize = chunksize
		self.sent = b''

	def recv(self, length):
		length = min(length, self.chunksize)
		chunk = self.data[:length]
		self.data = self.data[length:]
		return chunk
		
	def sendall(self, data):
		self.sent += data

	def close(self):
		pass

class TestBaseLDAPRequestHandler(unittest.TestCase):
	def test_handle(self):
		req = bytes(ldap.LDAPMessage(messageID=1, protocolOp=ldap.SearchRequest()))
		msglen = len(req)
		req += bytes(ldap.LDAPMessage(messageID=2, protocolOp=ldap.SearchRequest()))
		resp1 = bytes(ldap.LDAPMessage(messageID=1, protocolOp=ldap.SearchResultDone(ldap.LDAPResultCode.success)))
		resp2 = bytes(ldap.LDAPMessage(messageID=2, protocolOp=ldap.SearchResultDone(ldap.LDAPResultCode.success)))
		resp = resp1 + resp2
		# Chunking
		conn = MockConnection(req, 4096)
		BaseLDAPRequestHandler(conn, '', None).handle()
		self.assertEqual(conn.sent, resp)
		conn = MockConnection(req, msglen)
		BaseLDAPRequestHandler(conn, '', None).handle()
		self.assertEqual(conn.sent, resp)
		conn = MockConnection(req, 1)
		BaseLDAPRequestHandler(conn, '', None).handle()
		self.assertEqual(conn.sent, resp)
		conn = MockConnection(req, 15)
		BaseLDAPRequestHandler(conn, '', None).handle()
		self.assertEqual(conn.sent, resp)
		# No data
		conn = MockConnection(b'', 4096)
		BaseLDAPRequestHandler(conn, '', None).handle()
		self.assertEqual(conn.sent, b'')
		# Hangup/incomplete message
		conn = MockConnection(req[:-1], 4096)
		BaseLDAPRequestHandler(conn, '', None).handle()
		self.assertEqual(conn.sent, resp1)
		# Invalid message
		req = bytes(ldap.LDAPMessage(messageID=1, protocolOp=ldap.SearchRequest()))
		req = req[:7] + b'0xab' + req[8:]
		resp = bytes(ldap.LDAPMessage(messageID=1, protocolOp=ldap.SearchResultDone(ldap.LDAPResultCode.protocolError)))
		conn = MockConnection(req, 4096)
		BaseLDAPRequestHandler(conn, '', None).handle()
		self.assertEqual(conn.sent, resp)
		# Unrecoverable invalid message
		conn = MockConnection(b'\x00\xff', 4096)
		with self.assertRaises(ValueError):
			BaseLDAPRequestHandler(conn, '', None).handle()

class TestLDAPRequestHandler(unittest.TestCase):
	def test_session_python_ldap3(self):
		class RequestHandler(LDAPRequestHandler):
			def handle(self):
				pass
			def do_bind_simple_authenticated(self, dn, password):
				return dn == 'cn=service,ou=system,dc=example,dc=com' and password == b'foobar'
		# conn = ldap3.Connection(server, 'cn=service,ou=system,dc=example,dc=com', 'foobar')
		# conn.bind()
		# conn.search('ou=users,dc=example,dc=com', '(uid=testuser)', attributes=[ldap3.ALL_ATTRIBUTES])
		# conn.unbind()
		handler = RequestHandler(None, None, None)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'08\x02\x01\x1e`3\x02\x01\x03\x04&cn=service,ou=system,dc=example,dc=com\x80\x06foobar')[0]))
		self.assertEqual(len(resps), 1)
		self.assertIsInstance(resps[0].protocolOp, ldap.BindResponse)
		self.assertEqual(resps[0].protocolOp.resultCode, ldap.LDAPResultCode.success)
		# ldap3 automatically fetches rootdse and subschema per default
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0;\x02\x01\x1fc6\x04\x00\n\x01\x00\n\x01\x03\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectClass0\x16\x04\x11subschemaSubentry\x04\x01+')[0]))
		self.assertEqual(len(resps), 2)
		self.assertIsInstance(resps[0].protocolOp, ldap.SearchResultEntry)
		self.assertIsInstance(resps[1].protocolOp, ldap.SearchResultDone)
		self.assertEqual(resps[1].protocolOp.resultCode, ldap.LDAPResultCode.success)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0\x81\xe4\x02\x01 c\x81\xde\x04\x0ccn=Subschema\n\x01\x00\n\x01\x03\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa3\x18\x04\x0bobjectClass\x04\tsubschema0\x81\xa4\x04\robjectClasses\x04\x0eattributeTypes\x04\x0cldapSyntaxes\x04\rmatchingRules\x04\x0fmatchingRuleUse\x04\x0fdITContentRules\x04\x11dITStructureRules\x04\tnameForms\x04\x0fcreateTimestamp\x04\x0fmodifyTimestamp\x04\x01*\x04\x01+')[0]))
		self.assertEqual(len(resps), 2)
		self.assertIsInstance(resps[0].protocolOp, ldap.SearchResultEntry)
		self.assertIsInstance(resps[1].protocolOp, ldap.SearchResultDone)
		self.assertEqual(resps[1].protocolOp.resultCode, ldap.LDAPResultCode.success)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0F\x02\x01!cA\x04\x1aou=users,dc=example,dc=com\n\x01\x02\n\x01\x03\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa3\x0f\x04\x03uid\x04\x08testuser0\x03\x04\x01*')[0]))
		self.assertEqual(len(resps), 1)
		self.assertIsInstance(resps[0].protocolOp, ldap.SearchResultDone)
		self.assertEqual(resps[0].protocolOp.resultCode, ldap.LDAPResultCode.success)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0\x05\x02\x01"B\x00')[0]))
		self.assertEqual(len(resps), 0)

	def test_session_openldap_utils(self):
		class RequestHandler(LDAPRequestHandler):
			def handle(self):
				pass
			supports_sasl_plain = True
			def do_bind_sasl_plain(self, identity, password, authzid=None):
				return identity == 'service' and password == 'foobar' and (authzid is None or authzid == 'service')
		# ldapsearch -x -b '' -s subtree '(&(objectClass=person)(memberof=cn=users,ou=groups,dc=example,dc=com))'
		handler = RequestHandler(None, None, None)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0\x0c\x02\x01\x01`\x07\x02\x01\x03\x04\x00\x80\x00')[0]))
		self.assertEqual(len(resps), 1)
		self.assertIsInstance(resps[0].protocolOp, ldap.BindResponse)
		self.assertEqual(resps[0].protocolOp.resultCode, ldap.LDAPResultCode.success)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0c\x02\x01\x02c^\x04\x00\n\x01\x02\n\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa0I\xa3\x15\x04\x0bobjectClass\x04\x06person\xa30\x04\x08memberof\x04$cn=users,ou=groups,dc=example,dc=com0\x00')[0]))
		self.assertEqual(len(resps), 1)
		self.assertIsInstance(resps[0].protocolOp, ldap.SearchResultDone)
		self.assertEqual(resps[0].protocolOp.resultCode, ldap.LDAPResultCode.success)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0\x05\x02\x01\x03B\x00')[0]))
		self.assertEqual(len(resps), 0)
		# ldapsearch -x -MM -b '' -s subtree '(objectClass=*)'
		handler = RequestHandler(None, None, None)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0\x0c\x02\x01\x01`\x07\x02\x01\x03\x04\x00\x80\x00')[0]))
		self.assertEqual(len(resps), 1)
		self.assertIsInstance(resps[0].protocolOp, ldap.BindResponse)
		self.assertEqual(resps[0].protocolOp.resultCode, ldap.LDAPResultCode.success)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0E\x02\x01\x02c \x04\x00\n\x01\x02\n\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectClass0\x00\xa0\x1e0\x1c\x04\x172.16.840.1.113730.3.4.2\x01\x01\xff')[0]))
		self.assertEqual(len(resps), 1)
		self.assertIsInstance(resps[0].protocolOp, ldap.SearchResultDone)
		self.assertEqual(resps[0].protocolOp.resultCode, ldap.LDAPResultCode.unavailableCriticalExtension)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0\x05\x02\x01\x03B\x00')[0]))
		self.assertEqual(len(resps), 0)
		# ldapsearch -U service -X service -b '' -s base '(objectClass=*)'
		handler = RequestHandler(None, None, None)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0>\x02\x01\x01c9\x04\x00\n\x01\x00\n\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectclass0\x19\x04\x17supportedSASLMechanisms')[0]))
		self.assertEqual(len(resps), 2)
		self.assertIsInstance(resps[0].protocolOp, ldap.SearchResultEntry)
		self.assertIsInstance(resps[1].protocolOp, ldap.SearchResultDone)
		self.assertEqual(resps[1].protocolOp.resultCode, ldap.LDAPResultCode.success)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0+\x02\x01\x02`&\x02\x01\x03\x04\x00\xa3\x1f\x04\x05PLAIN\x04\x16service\x00service\x00foobar')[0]))
		self.assertEqual(len(resps), 1)
		self.assertIsInstance(resps[0].protocolOp, ldap.BindResponse)
		self.assertEqual(resps[0].protocolOp.resultCode, ldap.LDAPResultCode.success)
		resps = list(handler.handle_message(ldap.ShallowLDAPMessage.from_ber(b'0\x05\x02\x01\x03B\x00')[0]))
		self.assertEqual(len(resps), 0)

	def test_search(self):
		class MockObject:
			def __init__(_self, search_result=None):
				_self.search_result = search_result

			def search(_self, base_obj, scope, filter_obj, attributes, types_only):
				self.assertEqual(base_obj, 'cn=Test,dc=example,dc=com')
				self.assertEqual(scope, ldap.SearchScope.singleLevel)
				self.assertEqual(ldap.Filter.to_ber(filter_obj), ldap.Filter.to_ber(ldap.FilterPresent('foobar')))
				return _self.search_result

		class RequestHandler(LDAPRequestHandler):
			def handle(self):
				pass

			def do_search(_self, base_obj, scope, filter_obj):
				self.assertEqual(base_obj, 'cn=Test,dc=example,dc=com')
				self.assertEqual(scope, ldap.SearchScope.singleLevel)
				self.assertEqual(ldap.Filter.to_ber(filter_obj), ldap.Filter.to_ber(ldap.FilterPresent('foobar')))
				yield MockObject(ldap.SearchResultEntry('cn=Test1,dc=example,dc=com'))
				yield MockObject(None)
				yield MockObject(ldap.SearchResultEntry('cn=Test2,dc=example,dc=com'))

		handler = RequestHandler(None, None, None)
		resps = list(handler.handle_search(ldap.SearchRequest('cn=Test,dc=example,dc=com', ldap.SearchScope.singleLevel, filter=ldap.FilterPresent('foobar')), []))
		self.assertEqual(len(resps), 3)
		self.assertEqual(ldap.ProtocolOp.to_ber(resps[0]), ldap.ProtocolOp.to_ber(ldap.SearchResultEntry('cn=Test1,dc=example,dc=com')))
		self.assertEqual(ldap.ProtocolOp.to_ber(resps[1]), ldap.ProtocolOp.to_ber(ldap.SearchResultEntry('cn=Test2,dc=example,dc=com')))
		self.assertEqual(ldap.ProtocolOp.to_ber(resps[2]), ldap.ProtocolOp.to_ber(ldap.SearchResultDone()))

	def test_compare(self):
		class MockObject:
			def __init__(_self, result=None):
				_self.result = result

			def compare(_self, dn, attribute, value):
				self.assertEqual(dn, 'cn=Test,dc=example,dc=com')
				self.assertEqual(attribute, 'foo')
				self.assertEqual(value, b'bar')
				if isinstance(_self.result, Exception):
					raise _self.result
				return _self.result

		class RequestHandler(LDAPRequestHandler):
			def handle(self):
				pass

			def do_search(_self, base_obj, scope, filter_obj):
				self.assertEqual(base_obj, 'cn=Test,dc=example,dc=com')
				if _self.mode == 'true':
					yield MockObject(exceptions.LDAPNoSuchObject())
					yield MockObject(exceptions.LDAPNoSuchObject())
					yield MockObject(True)
					yield MockObject(exceptions.LDAPNoSuchObject())
				elif _self.mode == 'false':
					yield MockObject(exceptions.LDAPNoSuchObject())
					yield MockObject(exceptions.LDAPNoSuchObject())
					yield MockObject(False)
					yield MockObject(exceptions.LDAPNoSuchObject())
				elif _self.mode == 'empty':
					pass
				elif _self.mode == 'notfound':
					yield MockObject(exceptions.LDAPNoSuchObject())
					yield MockObject(exceptions.LDAPNoSuchObject())
				elif _self.mode == 'error':
					yield MockObject(exceptions.LDAPNoSuchObject())
					yield MockObject(exceptions.LDAPUndefinedAttributeType())
					yield MockObject(exceptions.LDAPNoSuchObject())

		handler = RequestHandler(None, None, None)
		handler.mode = 'true'
		resps = list(handler.handle_compare(ldap.CompareRequest('cn=Test,dc=example,dc=com', ava=ldap.AttributeValueAssertion('foo', b'bar'))))
		self.assertEqual(len(resps), 1)
		self.assertEqual(ldap.ProtocolOp.to_ber(resps[0]), ldap.ProtocolOp.to_ber(ldap.CompareResponse(ldap.LDAPResultCode.compareTrue)))

		handler.mode = 'false'
		resps = list(handler.handle_compare(ldap.CompareRequest('cn=Test,dc=example,dc=com', ava=ldap.AttributeValueAssertion('foo', b'bar'))))
		self.assertEqual(len(resps), 1)
		self.assertEqual(ldap.ProtocolOp.to_ber(resps[0]), ldap.ProtocolOp.to_ber(ldap.CompareResponse(ldap.LDAPResultCode.compareFalse)))

		handler.mode = 'empty'
		with self.assertRaises(exceptions.LDAPNoSuchObject):
			resps = list(handler.handle_compare(ldap.CompareRequest('cn=Test,dc=example,dc=com', ava=ldap.AttributeValueAssertion('foo', b'bar'))))
			self.assertEqual(len(resps), 1)
			self.assertEqual(ldap.ProtocolOp.to_ber(resps[0]), ldap.ProtocolOp.to_ber(ldap.CompareResponse(ldap.LDAPResultCode.noSuchObject)))

		handler.mode = 'notfound'
		with self.assertRaises(exceptions.LDAPNoSuchObject):
			resps = list(handler.handle_compare(ldap.CompareRequest('cn=Test,dc=example,dc=com', ava=ldap.AttributeValueAssertion('foo', b'bar'))))
			self.assertEqual(len(resps), 1)
			self.assertEqual(ldap.ProtocolOp.to_ber(resps[0]), ldap.ProtocolOp.to_ber(ldap.CompareResponse(ldap.LDAPResultCode.noSuchObject)))

		handler.mode = 'error'
		with self.assertRaises(exceptions.LDAPUndefinedAttributeType):
			resps = list(handler.handle_compare(ldap.CompareRequest('cn=Test,dc=example,dc=com', ava=ldap.AttributeValueAssertion('foo', b'bar'))))
			self.assertEqual(len(resps), 1)
			self.assertEqual(ldap.ProtocolOp.to_ber(resps[0]), ldap.ProtocolOp.to_ber(ldap.CompareResponse(ldap.LDAPResultCode.undefinedAttributeType)))
