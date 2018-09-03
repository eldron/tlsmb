from tlslite.handshakesettings import *
from tlslite.messages import *
from tlslite.extensions import *
from tlslite.utils.codec import *
from tlslite import TLSConnection
from tlslite.session import *
from tlslite.tlsconnection import is_valid_hostname
from tlslite.handshakehelpers import *
import select
import os.path
import time

from mb_ec_util import *

MB_STATE_INITIAL_WAIT_CLIENT_HELLO = 0
MB_STATE_INITIAL_WAIT_SERVER_HELLO = 1
MB_STATE_RETRY_WAIT_CLIENT_HELLO = 2
MB_STATE_RETRY_WAIT_SERVER_HELLO = 3
MB_STATE_HANDSHAKE_DONE = 4 # set state to this when we received client finished
MB_STATE_HANDSHAKE_ABORT = 5
MB_STATE_WAIT_ENCRYPTED_EXTENSIONS = 6
MB_STATE_WAIT_CERTIFICATE = 7 # when PSK is not used
MB_STATE_WAIT_CERTIFICATE_VERIFY = 8 # when PSK is not used
MB_STATE_WAIT_SERVER_FINISHED = 9
MB_STATE_WAIT_CLIENT_FINISHED = 10

print_debug_info = False

def no_accumulate_forward_data(request, sock):
	request.setblocking(0)
	sock.setblocking(0)
	inputs = [request, sock]
	sock_data_len = 0
	while inputs:
		readable, writable, exceptional = select.select(inputs, [], inputs)
		for s in readable:
			data = s.recv(30000)
			if data:
				if s == request:
					sock.sendall(data)
				else:
					sock_data_len += len(data)
					print 'sock_data_len = ' + str(sock_data_len)
					print 'datalen = ' + str(len(data))
					request.sendall(data)
					# if sock_data_len < 20000:
					# 	request.sendall(data)
			else:
				s.close()
				inputs.remove(s)
		for s in exceptional:
			s.close()
			inputs.remove(s)

# functions for testing
def fake_handshakeClientCert(connection, certChain=None, privateKey=None,
							session=None, settings=None, checker=None,
							nextProtos=None, reqTack=True, serverName=None,
							async_=False, alpn=None):
		"""Perform a certificate-based handshake in the role of client.

		This function performs an SSL or TLS handshake.  The server
		will authenticate itself using an X.509 certificate
		chain.  If the handshake succeeds, the server's certificate
		chain will be stored in the session's serverCertChain attribute.
		Unless a checker object is passed in, this function does no
		validation or checking of the server's certificate chain.

		If the server requests client authentication, the
		client will send the passed-in certificate chain, and use the
		passed-in private key to authenticate itself.  If no
		certificate chain and private key were passed in, the client
		will attempt to proceed without client authentication.  The
		server may or may not allow this.

		If the function completes without raising an exception, the
		TLS connection will be open and available for data transfer.

		If an exception is raised, the connection will have been
		automatically closed (if it was ever open).

		:type certChain: ~tlslite.x509certchain.X509CertChain
		:param certChain: The certificate chain to be used if the
			server requests client authentication.

		:type privateKey: ~tlslite.utils.rsakey.RSAKey
		:param privateKey: The private key to be used if the server
			requests client authentication.

		:type session: ~tlslite.session.Session
		:param session: A TLS session to attempt to resume.  If the
			resumption does not succeed, a full handshake will be
			performed.

		:type settings: ~tlslite.handshakesettings.HandshakeSettings
		:param settings: Various settings which can be used to control
			the ciphersuites, certificate types, and SSL/TLS versions
			offered by the client.

		:type checker: ~tlslite.checker.Checker
		:param checker: A Checker instance.  This instance will be
			invoked to examine the other party's authentication
			credentials, if the handshake completes succesfully.

		:type nextProtos: list of str
		:param nextProtos: A list of upper layer protocols ordered by
			preference, to use in the Next-Protocol Negotiation Extension.

		:type reqTack: bool
		:param reqTack: Whether or not to send a "tack" TLS Extension,
			requesting the server return a TackExtension if it has one.

		:type serverName: string
		:param serverName: The ServerNameIndication TLS Extension.

		:type async_: bool
		:param async_: If False, this function will block until the
			handshake is completed.  If True, this function will return a
			generator.  Successive invocations of the generator will
			return 0 if it is waiting to read from the socket, 1 if it is
			waiting to write to the socket, or will raise StopIteration if
			the handshake operation is completed.

		:type alpn: list of bytearrays
		:param alpn: protocol names to advertise to server as supported by
			client in the Application Layer Protocol Negotiation extension.
			Example items in the array include b'http/1.1' or b'h2'.

		:rtype: None or an iterable
		:returns: If 'async_' is True, a generator object will be
			returned.

		:raises socket.error: If a socket error occurs.
		:raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
			without a preceding alert.
		:raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
		:raises tlslite.errors.TLSAuthenticationError: If the checker
			doesn't like the other party's authentication credentials.
		"""
		handshaker = \
				fake_handshakeClientAsync(connection, certParams=(certChain, privateKey),
										   session=session, settings=settings,
										   checker=checker,
										   serverName=serverName,
										   nextProtos=nextProtos,
										   reqTack=reqTack,
										   alpn=alpn)
		# The handshaker is a Python Generator which executes the handshake.
		# It allows the handshake to be run in a "piecewise", asynchronous
		# fashion, returning 1 when it is waiting to able to write, 0 when
		# it is waiting to read.
		#
		# If 'async_' is True, the generator is returned to the caller,
		# otherwise it is executed to completion here.
		if async_:
			return handshaker
		for result in handshaker:
			pass

def fake_handshakeClientAsync(connection, srpParams=(), certParams=(), anonParams=(),
							  session=None, settings=None, checker=None,
							  nextProtos=None, serverName=None, reqTack=True,
							  alpn=None):

		handshaker = fake_handshakeClientAsyncHelper(connection, srpParams=srpParams,
				certParams=certParams,
				anonParams=anonParams,
				session=session,
				settings=settings,
				serverName=serverName,
				nextProtos=nextProtos,
				reqTack=reqTack,
				alpn=alpn)
		for result in connection._handshakeWrapperAsync(handshaker, checker):
			yield result

def fake_handshakeClientAsyncHelper(connection, srpParams, certParams, anonParams,
							   session, settings, serverName, nextProtos,
							   reqTack, alpn):

		connection._handshakeStart(client=True)

		#Unpack parameters
		srpUsername = None      # srpParams[0]
		password = None         # srpParams[1]
		clientCertChain = None  # certParams[0]
		privateKey = None       # certParams[1]

		# Allow only one of (srpParams, certParams, anonParams)
		if srpParams:
			assert(not certParams)
			assert(not anonParams)
			srpUsername, password = srpParams
		if certParams:
			assert(not srpParams)
			assert(not anonParams)            
			clientCertChain, privateKey = certParams
		if anonParams:
			assert(not srpParams)         
			assert(not certParams)

		#Validate parameters
		if srpUsername and not password:
			raise ValueError("Caller passed a username but no password")
		if password and not srpUsername:
			raise ValueError("Caller passed a password but no username")
		if clientCertChain and not privateKey:
			raise ValueError("Caller passed a cert_chain but no privateKey")
		if privateKey and not clientCertChain:
			raise ValueError("Caller passed a privateKey but no cert_chain")
		if reqTack:
			if not tackpyLoaded:
				reqTack = False
			if not settings or not settings.useExperimentalTackExtension:
				reqTack = False
		if nextProtos is not None:
			if len(nextProtos) == 0:
				raise ValueError("Caller passed no nextProtos")
		if alpn is not None and not alpn:
			raise ValueError("Caller passed empty alpn list")
		# reject invalid hostnames but accept empty/None ones
		if serverName and not is_valid_hostname(serverName):
			raise ValueError("Caller provided invalid server host name: {0}"
							 .format(serverName))

		# Validates the settings and filters out any unsupported ciphers
		# or crypto libraries that were requested        
		if not settings:
			settings = HandshakeSettings()
		settings = settings.validate()
		connection.sock.padding_cb = settings.padding_cb

		if clientCertChain:
			if not isinstance(clientCertChain, X509CertChain):
				raise ValueError("Unrecognized certificate type")
			if "x509" not in settings.certificateTypes:
				raise ValueError("Client certificate doesn't match "\
								 "Handshake Settings")
								  
		if session:
			# session.valid() ensures session is resumable and has 
			# non-empty sessionID
			if not session.valid():
				session = None #ignore non-resumable sessions...
			elif session.resumable: 
				if session.srpUsername != srpUsername:
					raise ValueError("Session username doesn't match")
				if session.serverName != serverName:
					raise ValueError("Session servername doesn't match")

		#Add Faults to parameters
		if srpUsername and connection.fault == Fault.badUsername:
			srpUsername += bytearray(b"GARBAGE")
		if password and connection.fault == Fault.badPassword:
			password += bytearray(b"GARBAGE")

		# Tentatively set the client's record version.
		# We'll use this for the ClientHello, and if an error occurs
		# parsing the Server Hello, we'll use this version for the response
		# in TLS 1.3 it always needs to be set to TLS 1.0
		connection.version = \
			(3, 1) if settings.maxVersion > (3, 3) else settings.maxVersion

		# OK Start sending messages!
		# *****************************

		# Send the ClientHello.
		for result in fake_clientSendClientHello(connection, settings, session, 
										srpUsername, srpParams, certParams,
										anonParams, serverName, nextProtos,
										reqTack, alpn):
			if result in (0,1): yield result
			else: break
		clientHello = result
		
		#Get the ServerHello.
		for result in connection._clientGetServerHello(settings, session,
												 clientHello):
			if result in (0,1): yield result
			else: break
		serverHello = result
		cipherSuite = serverHello.cipher_suite

		# if we're doing tls1.3, use the new code as the negotiation is much
		# different
		ext = serverHello.getExtension(ExtensionType.supported_versions)
		if ext and ext.version > (3, 3):
			for result in connection._clientTLS13Handshake(settings, session,
													 clientHello,
													 serverHello):
				if result in (0, 1):
					yield result
				else:
					break
			if result in ["finished", "resumed_and_finished"]:
				connection._handshakeDone(resumed=(result == "resumed_and_finished"))
				connection._serverRandom = serverHello.random
				connection._clientRandom = clientHello.random
				return
			else:
				raise Exception("unexpected return")

		# Choose a matching Next Protocol from server list against ours
		# (string or None)
		nextProto = connection._clientSelectNextProto(nextProtos, serverHello)

		# Check if server selected encrypt-then-MAC
		if serverHello.getExtension(ExtensionType.encrypt_then_mac):
			connection._recordLayer.encryptThenMAC = True

		if serverHello.getExtension(ExtensionType.extended_master_secret):
			connection.extendedMasterSecret = True

		#If the server elected to resume the session, it is handled here.
		for result in connection._clientResume(session, serverHello, 
						clientHello.random, 
						settings.cipherImplementations,
						nextProto):
			if result in (0,1): yield result
			else: break
		if result == "resumed_and_finished":
			connection._handshakeDone(resumed=True)
			connection._serverRandom = serverHello.random
			connection._clientRandom = clientHello.random
			# alpn protocol is independent of resumption and renegotiation
			# and needs to be negotiated every time
			alpnExt = serverHello.getExtension(ExtensionType.alpn)
			if alpnExt:
				session.appProto = alpnExt.protocol_names[0]
			return

		#If the server selected an SRP ciphersuite, the client finishes
		#reading the post-ServerHello messages, then derives a
		#premasterSecret and sends a corresponding ClientKeyExchange.
		if cipherSuite in CipherSuite.srpAllSuites:
			keyExchange = SRPKeyExchange(cipherSuite, clientHello,
										 serverHello, None, None,
										 srpUsername=srpUsername,
										 password=password,
										 settings=settings)

		#If the server selected an anonymous ciphersuite, the client
		#finishes reading the post-ServerHello messages.
		elif cipherSuite in CipherSuite.dhAllSuites:
			keyExchange = DHE_RSAKeyExchange(cipherSuite, clientHello,
											 serverHello, None)

		elif cipherSuite in CipherSuite.ecdhAllSuites:
			acceptedCurves = connection._curveNamesToList(settings)
			keyExchange = ECDHE_RSAKeyExchange(cipherSuite, clientHello,
											   serverHello, None,
											   acceptedCurves)

		#If the server selected a certificate-based RSA ciphersuite,
		#the client finishes reading the post-ServerHello messages. If 
		#a CertificateRequest message was sent, the client responds with
		#a Certificate message containing its certificate chain (if any),
		#and also produces a CertificateVerify message that signs the 
		#ClientKeyExchange.
		else:
			keyExchange = RSAKeyExchange(cipherSuite, clientHello,
										 serverHello, None)

		# we'll send few messages here, send them in single TCP packet
		connection.sock.buffer_writes = True
		for result in connection._clientKeyExchange(settings, cipherSuite,
											  clientCertChain,
											  privateKey,
											  serverHello.certificate_type,
											  serverHello.tackExt,
											  clientHello.random,
											  serverHello.random,
											  keyExchange):
			if result in (0, 1):
				yield result
			else: break
		(premasterSecret, serverCertChain, clientCertChain,
		 tackExt) = result

		#After having previously sent a ClientKeyExchange, the client now
		#initiates an exchange of Finished messages.
		# socket buffering is turned off in _clientFinished
		for result in connection._clientFinished(premasterSecret,
							clientHello.random, 
							serverHello.random,
							cipherSuite, settings.cipherImplementations,
							nextProto):
				if result in (0,1): yield result
				else: break
		masterSecret = result

		# check if an application layer protocol was negotiated
		alpnProto = None
		alpnExt = serverHello.getExtension(ExtensionType.alpn)
		if alpnExt:
			alpnProto = alpnExt.protocol_names[0]

		# Create the session object which is used for resumptions
		connection.session = Session()
		connection.session.create(masterSecret, serverHello.session_id, cipherSuite,
							srpUsername, clientCertChain, serverCertChain,
							tackExt, (serverHello.tackExt is not None),
							serverName,
							encryptThenMAC=connection._recordLayer.encryptThenMAC,
							extendedMasterSecret=connection.extendedMasterSecret,
							appProto=alpnProto)
		connection._handshakeDone(resumed=False)
		connection._serverRandom = serverHello.random
		connection._clientRandom = clientHello.random

def fake_clientSendClientHello(connection, settings, session, srpUsername,
								srpParams, certParams, anonParams,
								serverName, nextProtos, reqTack, alpn):
		#Initialize acceptable ciphersuites
		cipherSuites = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
		if srpParams:
			cipherSuites += CipherSuite.getSrpAllSuites(settings)
		elif certParams:
			cipherSuites += CipherSuite.getTLS13Suites(settings)
			cipherSuites += CipherSuite.getEcdheCertSuites(settings)
			cipherSuites += CipherSuite.getDheCertSuites(settings)
			cipherSuites += CipherSuite.getCertSuites(settings)
		elif anonParams:
			cipherSuites += CipherSuite.getEcdhAnonSuites(settings)
			cipherSuites += CipherSuite.getAnonSuites(settings)
		else:
			assert False

		#Add any SCSVs. These are not real cipher suites, but signaling
		#values which reuse the cipher suite field in the ClientHello.
		wireCipherSuites = list(cipherSuites)
		if settings.sendFallbackSCSV:
			wireCipherSuites.append(CipherSuite.TLS_FALLBACK_SCSV)

		#Initialize acceptable certificate types
		certificateTypes = settings.getCertificateTypes()

		extensions = []

		#Initialize TLS extensions
		if settings.useEncryptThenMAC:
			extensions.append(TLSExtension().\
							  create(ExtensionType.encrypt_then_mac,
									 bytearray(0)))
		if settings.useExtendedMasterSecret:
			extensions.append(TLSExtension().create(ExtensionType.
													extended_master_secret,
													bytearray(0)))
		groups = []
		#Send the ECC extensions only if we advertise ECC ciphers
		if next((cipher for cipher in cipherSuites \
				if cipher in CipherSuite.ecdhAllSuites), None) is not None:
			groups.extend(connection._curveNamesToList(settings))
			extensions.append(ECPointFormatsExtension().\
							  create([ECPointFormat.uncompressed]))
		# Advertise FFDHE groups if we have DHE ciphers
		if next((cipher for cipher in cipherSuites
				 if cipher in CipherSuite.dhAllSuites), None) is not None:
			groups.extend(connection._groupNamesToList(settings))
		# Send the extension only if it will be non empty
		if groups:
			extensions.append(SupportedGroupsExtension().create(groups))
		# In TLS1.2 advertise support for additional signature types
		if settings.maxVersion >= (3, 3):
			sigList = connection._sigHashesToList(settings)
			assert len(sigList) > 0
			extensions.append(SignatureAlgorithmsExtension().\
							  create(sigList))
		# if we know any protocols for ALPN, advertise them
		if alpn:
			extensions.append(ALPNExtension().create(alpn))

		session_id = bytearray()

		g_b, b = stateless_gen_g_b_for_client()

		# when TLS 1.3 advertised, add key shares, set fake session_id
		if next((i for i in settings.versions if i > (3, 3)), None):
			session_id = getRandomBytes(32)
			extensions.append(SupportedVersionsExtension().
							  create(settings.versions))

			shares = []
			for group_name in settings.keyShares:
				group_id = getattr(GroupName, group_name)
				if group_id == GroupName.x25519 or group_id == GroupName.secp256r1 or group_id == GroupName.secp384r1 or group_id == GroupName.secp521r1:
					#key_share = naive_genKeyShareEntry(group_id, (3, 4))
					#key_share = asymmetric_genKeyShare(group_id, (3, 4))
					key_share = stateless_genKeyShareEntry(group_id, (3, 4), b)
				else:
					key_share = connection._genKeyShareEntry(group_id, (3, 4))

				shares.append(key_share)
			# if TLS 1.3 is enabled, key_share must always be sent
			# (unless only static PSK is used)
			extensions.append(ClientKeyShareExtension().create(shares))

			# add info on types of PSKs supported (also used for
			# NewSessionTicket so send basically always)
			ext = PskKeyExchangeModesExtension().create(
				[PskKeyExchangeMode.psk_ke, PskKeyExchangeMode.psk_dhe_ke])
			extensions.append(ext)

		# don't send empty list of extensions or extensions in SSLv3
		if not extensions or settings.maxVersion == (3, 0):
			extensions = None

		sent_version = min(settings.maxVersion, (3, 3))

		#Either send ClientHello (with a resumable session)...
		if session and session.sessionID:
			#If it's resumable, then its
			#ciphersuite must be one of the acceptable ciphersuites
			if session.cipherSuite not in cipherSuites:
				raise ValueError("Session's cipher suite not consistent "\
								 "with parameters")
			else:
				clientHello = ClientHello()
				clientHello.create(sent_version, g_b,
								   session.sessionID, wireCipherSuites,
								   certificateTypes, 
								   session.srpUsername,
								   reqTack, nextProtos is not None,
								   session.serverName,
								   extensions=extensions)
				# clientHello.create(sent_version, getRandomBytes(32),
				#                    session.sessionID, wireCipherSuites,
				#                    certificateTypes, 
				#                    session.srpUsername,
				#                    reqTack, nextProtos is not None,
				#                    session.serverName,
				#                    extensions=extensions)

		#Or send ClientHello (without)
		else:
			clientHello = ClientHello()
			clientHello.create(sent_version, g_b,
							   session_id, wireCipherSuites,
							   certificateTypes, 
							   srpUsername,
							   reqTack, nextProtos is not None, 
							   serverName,
							   extensions=extensions)
			# clientHello.create(sent_version, getRandomBytes(32),
			#                    session_id, wireCipherSuites,
			#                    certificateTypes, 
			#                    srpUsername,
			#                    reqTack, nextProtos is not None, 
			#                    serverName,
			#                    extensions=extensions)

		# Check if padding extension should be added
		# we want to add extensions even when using just SSLv3
		if settings.usePaddingExtension:
			HandshakeHelpers.alignClientHelloPadding(clientHello)

		# because TLS 1.3 PSK is sent in ClientHello and signs the ClientHello
		# we need to send it as the last extension
		if (settings.pskConfigs or (session and session.tickets)) \
				and settings.maxVersion >= (3, 4):
			ext = PreSharedKeyExtension()
			idens = []
			binders = []
			# if we have a previous session, include it in PSKs too
			if session and session.tickets:
				now = time.time()
				# clean the list from obsolete ones
				# RFC says that the tickets MUST NOT be cached longer than
				# 7 days
				session.tickets[:] = (i for i in session.tickets if
									  i.time + i.ticket_lifetime > now and
									  i.time + 7 * 24 * 60 * 60 > now)
				if session.tickets:
					ticket = session.tickets[0]

					ticket_time = int(ticket.time + ticket.ticket_age_add) \
						% 2**32
					idens.append(PskIdentity().create(ticket.ticket,
													  ticket_time))
					binder_len = 48 if session.cipherSuite in \
						CipherSuite.sha384PrfSuites else 32
					binders.append(bytearray(binder_len))
			for psk in settings.pskConfigs:
				# skip PSKs with no identities as they're TLS1.3 incompatible
				if not psk[0]:
					continue
				idens.append(PskIdentity().create(psk[0], 0))
				psk_hash = psk[2] if len(psk) > 2 else 'sha256'
				assert psk_hash in set(['sha256', 'sha384'])
				# create fake binder values to create correct length fields
				binders.append(bytearray(32 if psk_hash == 'sha256' else 48))

			if idens:
				ext.create(idens, binders)
				clientHello.extensions.append(ext)

				# for HRR case we'll need 1st CH and HRR in handshake hashes,
				# so pass them in, truncated CH will be added by the helpers to
				# the copy of the hashes
				HandshakeHelpers.update_binders(clientHello,
												connection._handshake_hash,
												settings.pskConfigs,
												session.tickets if session
												else None,
												session.resumptionMasterSecret
												if session else None)

		for result in connection._sendMsg(clientHello):
			yield result
		yield clientHello


class MBHandshakeState(object):
	def __init__(self):
		self.client_hello = None
		self.server_hello = None
		self.state = MB_STATE_INITIAL_WAIT_CLIENT_HELLO
		self.client_hello_retry_request = None
		self.retry_client_hello = None
		self.retry_server_hello = None
		self.settings = None
		# the 'fake' TLSConnection constructed from server_sock
		# used to mimic the behavior of real TLS 1.3 client
		self.server_connection = None
		# the 'fake' TLSConnection constructed from client_sock
		# used to mimic the behavior of real TLS 1.3 server
		self.client_connection = None 
		self.session = None
		self.sessionCache = None
		self.client_sock = None # the socket through which we connected with the real tls 1.3 client
		self.server_sock = None # the socket through which we connected with the tls 1.3 serve
		
		self.alpha = None # set this when we received server hello bytearray for x25519, long for secp curves
		self.prev_public_key = None # read this from file when we received server_hello
		self.curve_name = 'x25519' # set this when we received server hello
		self.mb_ec_private_key = None # calculate this when we received server hello
		self.prev_pubkey_filename = None # set this when we received server hello

		self.encrypted_extensions = None
		self.server_cert_chain = None
		self.certificate = None # the decrypted certificate we received from server_connection
		self.certificate_verify = None # the decrypted certificate verify we received from server_connection
		self.server_finished = None
		self.client_finished = None
		self.server_psk = None # set this when we received server hello from server_connection

		self.client_hello_parser = None
		self.retry_client_hello_parser = None
		self.hrr_parser = None
		self.server_hello_parser = None
		self.retry_server_hello_parser = None
		self.encrypted_extensions_parser = None
		self.certificate_parser = None
		self.certificate_verify_parser = None
		self.server_finished_parser = None
		self.client_finished_parser = None
		self.resuming = False

		# cache data to send
		self.to_server_list = []
		self.to_client_list = []

		# ipc socket
		self.inspection_client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.inspection_client_sock.connect('inspection_server')

		self.clear_tosend_list_interval = 0
		self.app_data_len = 0
		self.dec_interval = 0


	def clear_tosend_list(self, toserver):
		begin = time.time()
		if toserver:
			for tosend in self.to_server_list:
				header, data = tosend
				self.server_sock.sendall(header.write() + data)
			self.to_server_list = []
		else:
			for tosend in self.to_client_list:
				header, data = tosend
				self.client_sock.sendall(header.write() + data)
			self.to_client_list = []
		end = time.time()
		interval = 1000 * end - 1000 * begin
		self.clear_tosend_list_interval += interval
	
	def set_server_sock(self, sock):
		"""
		set the socket through which the middlebox connected with the tls 1.3 server
		also initializes self.server_connection
		"""
		self.server_sock = sock
		self.server_connection = TLSConnection(sock)
		# mimic real TLS 1.3 client
		self.server_connection._recordLayer.client = True

	def set_client_sock(self, sock):
		"""
		set the socket through which the middlebox connected with the real tls 1.3 client
		also initializes self.client_connection
		"""
		self.client_sock = sock
		self.client_connection = TLSConnection(sock)
		# mimic real TLS 1.3 server
		self.client_connection._recordLayer.client = False
	
	# # call this function in a for loop to get header, data
	# def get_TLSCipherText(self, from_server):
	#     """
	#     get TLSCipherText record
	#     header contains opaque_type, legacy_record_version, and length
	#     data contains opaque data
	#     """
	#     if from_server:
	#         connection = self.server_connection
	#     else:
	#         connection = self.client_connection
		
	#     result = None
	#     for result in connection._recordLayer._recordSocket.recv():
	#         if result in (0, 1):
	#             yield result
	#         else: break
	#     assert result is not None

	#     # we send the ciphertext to the other party
	#     header, data = result
	#     if from_server:
	#         self.client_sock.write(header + data)
	#     else:
	#         self.server_sock.write(header + data)
		
	#     yield result

	# def recvRecord(self, from_server):
	# 	if from_server:
	# 		record_layer = self.server_connection._recordLayer
	# 	else:
	# 		record_layer = self.client_connection._recordLayer
		
	# 	for r in record_layer.recvRecord():
	# 		if r in (0, 1):
	# 			yield r
	# 		else:
	# 			break

	# 	# (header, data) = r

	# 	# # we send the ciphertext to the other party
	# 	# if from_server:
	# 	# 	self.client_sock.sendall(header.write() + data)
	# 	# else:
	# 	# 	self.server_sock.sendall(header.write() + data)
			
	# 	yield r

	def recvRecord(self, from_server):
		"""
		Read, decrypt and check integrity of a single record

		:rtype: tuple
		:returns: message header and decrypted message payload
		:raises TLSDecryptionFailed: when decryption of data failed
		:raises TLSBadRecordMAC: when record has bad MAC or padding
		:raises socket.error: when reading from socket was unsuccessful
		"""
		if from_server:
			record_layer = self.server_connection._recordLayer
		else:
			record_layer = self.client_connection._recordLayer

		result = None
		for result in record_layer._recordSocket.recv():
			if result in (0, 1):
				yield result
			else: break
		assert result is not None

		(header, data) = result

		# we send the ciphertext to the other party
		if from_server:
			self.client_sock.sendall(header.write() + data)
		else:
			self.server_sock.sendall(header.write() + data)

		#time1 = time.time()
		# cache the cipher text data to send
		# send the data when inspection is done
		# if from_server:
		#     self.to_client_list.append((header, data))
		# else:
		#     self.to_server_list.append((header, data))

		if isinstance(header, RecordHeader2):
			data = record_layer._decryptSSL2(data, header.padding)
			if record_layer.handshake_finished:
				header.type = ContentType.application_data
		# in TLS 1.3, the other party may send an unprotected CCS message
		# at any point in connection
		elif record_layer._is_tls13_plus() and \
				header.type == ContentType.change_cipher_spec:
			pass
		elif record_layer._readState and \
			record_layer._readState.encContext and \
			record_layer._readState.encContext.isAEAD:
			#print 'is AEAD, to decrypt and unseal:'
			time1 = time.time()
			data = record_layer._decryptAndUnseal(header, data)
			time2 = time.time()
			self.dec_interval += (time2 - time1)
			#print 'dec interval = ' + str(self.dec_interval)
		elif record_layer._readState and record_layer._readState.encryptThenMAC:
			data = record_layer._macThenDecrypt(header.type, data)
		elif record_layer._readState and \
				record_layer._readState.encContext and \
				record_layer._readState.encContext.isBlockCipher:
			data = record_layer._decryptThenMAC(header.type, data)
		else:
			data = record_layer._decryptStreamThenMAC(header.type, data)

		# TLS 1.3 encrypts the type, CCS is not encrypted
		if record_layer._is_tls13_plus() and record_layer._readState and \
				record_layer._readState.encContext and\
				header.type != ContentType.change_cipher_spec:
			data, contentType = record_layer._tls13_de_pad(data)
			header = RecordHeader3().create((3, 4), contentType, len(data))

		# RFC 5246, section 6.2.1
		if len(data) > 2**14:
			raise TLSRecordOverflow()

		yield (header, Parser(data))

	# we need to implement our own getNextRecordFromSocket function
	# basically copied, remove send msg calls
	# data is already decrypted
	def _getNextRecordFromSocket(self, from_server):
		"""Read a record, handle errors"""
		if from_server:
			connection = self.server_connection
		else:
			connection = self.client_connection
		
		try:
			# otherwise... read the next record
			# connection._recordLayer.recvRecord() should not contain send msg calls
			# Read, decrypt and check integrity of a single record
			# connection._recordLayer.recvRecord decrypts depads and checks integrity of a record
			for result in self.recvRecord(from_server):
				if result in (0, 1):
					yield result
				else:
					break
		except TLSUnexpectedMessage as e:
			# for result in self._sendError(AlertDescription.unexpected_message):
			#     yield result
			print 'TLSUnexpectedMessage exception raised'
			print e
			yield 0
		except TLSRecordOverflow as e:
			# for result in self._sendError(AlertDescription.record_overflow):
			#     yield result
			print 'TLSRecordOverflow raised'
			print e
			yield 0
		except TLSIllegalParameterException as e:
			# for result in self._sendError(AlertDescription.illegal_parameter):
			#     yield result
			print 'TLSIllegalParameterException raised'
			print e
			yield 0
		except TLSDecryptionFailed as e:
			# for result in self._sendError(
			#         AlertDescription.decryption_failed,
			#         "Encrypted data not a multiple of blocksize"):
			#     yield result
			print 'TLSDecryptionFailed raised'
			print e
			yield 0
		except TLSBadRecordMAC as e:
			# for result in self._sendError(
			#         AlertDescription.bad_record_mac,
			#         "MAC failure (or padding failure)"):
			#     yield result
			print 'TLSBadRecordMAC raised'
			print e
			yield 0

		header, parser = result

		# RFC5246 section 6.2.1: Implementations MUST NOT send
		# zero-length fragments of content types other than Application
		# Data.
		if header.type != ContentType.application_data \
				and parser.getRemainingLength() == 0:
			# for result in self._sendError(
			#         AlertDescription.unexpected_message,
			#         "Received empty non-application data record"):
			#     yield result
			print 'received empty non-application data record'
			yield 0

		if header.type not in ContentType.all:
			# for result in self._sendError(\
			#         AlertDescription.unexpected_message, \
			#         "Received record with unknown ContentType"):
			#     yield result
			print 'received record with unknown ContentType'
			yield 0

		yield (header, parser)

	# we need to implement our own getNextRecord function
	# basiclly copied, remove send msg calls
	# Returns next record or next handshake message
	# data is decrypted and defragmented
	# we call this function to get client and server hello
	# needs to be called in a for loop
	def _getNextRecord(self, from_server):
		"""read next message from socket, defragment message"""
		if from_server:
			connection = self.server_connection
		else:
			connection = self.client_connection
		
		while True:
			# support for fragmentation
			# (RFC 5246 Section 6.2.1)
			# Because the Record Layer is completely separate from the messages
			# that traverse it, it should handle both application data and
			# hadshake data in the same way. For that we buffer the handshake
			# messages until they are completely read.
			# This makes it possible to handle both handshake data not aligned
			# to record boundary as well as handshakes longer than single
			# record.
			while True:
				# empty message buffer
				ret = connection._defragmenter.get_message()
				if ret is None:
					break
				header = RecordHeader3().create(connection.version, ret[0], 0)
				yield header, Parser(ret[1])

			# when the message buffer is empty, read next record from socket
			# we call our own _getNextRecordFromSocket function here
			for result in self._getNextRecordFromSocket(from_server):
				if result in (0, 1):
					yield result
				else:
					break

			header, parser = result

			# application data (and CCS in TLS1.3) isn't made out of messages,
			# pass it through
			if header.type == ContentType.application_data or \
					(connection.version > (3, 3) and
					 header.type == ContentType.change_cipher_spec):
				#yield (header, parser)
				
				# if from_server:
				#     print 'getNextRecord: received change cipher spec from server'
				# else:
				#     print 'getNextRecord: received change cipher spec from client'
				yield (header, parser)
			# If it's an SSLv2 ClientHello, we can return it as well, since
			# it's the only ssl2 type we support
			elif header.ssl2:
				yield (header, parser)
			else:
				# other types need to be put into buffers
				connection._defragmenter.add_data(header.type, parser.bytes)

	# the asymmetric version, the same with the naive version
	def asymmetric_get_client_hello(self):
		"""
		we read client hello from client_connection
		for client_connection: copy _pre_client_hello_handshake_hash, then update handshake hashes
		for server_connection: update handshake hashes
		"""
		if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO or self.state == MB_STATE_RETRY_WAIT_CLIENT_HELLO:
			pass
		else:
			print 'get_client_hello: incorrect state'
			return

		for result in self._getMsg(False, ContentType.handshake, HandshakeType.client_hello):
			if result in (0,1):
				#yield result
				pass
			else:
				break
		result, parser = result
		assert isinstance(result, ClientHello)
		client_hello = result

		# send client hello to server
		self.clear_tosend_list(True)

		# copy for calculating PSK binders
		self.client_connection._pre_client_hello_handshake_hash = self.client_connection._handshake_hash.copy()

		# update hashes
		self.client_connection._handshake_hash.update(parser.bytes)
		self.server_connection._handshake_hash.update(parser.bytes)

		if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO:
			self.client_hello = client_hello
			self.client_hello_parser = parser
		else:
			self.retry_client_hello = client_hello
			self.retry_client_hello_parser = parser
				
		self.settings = mb_get_settings(client_hello, None)
		self.session = mb_get_resumable_session(self.client_hello)
		# we need to set session for client_connection and server_connection
		self.client_connection.session = self.session
		self.server_connection.session = self.session

		# change state
		if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO:
			self.state = MB_STATE_INITIAL_WAIT_SERVER_HELLO
		else:
			self.state = MB_STATE_RETRY_WAIT_SERVER_HELLO

	# the stateless version
	# we calculate ec private key when we received server hello
	def stateless_get_client_hello(self):
		"""
		we read client hello from client_connection
		for client_connection: copy _pre_client_hello_handshake_hash, then update handshake hashes
		for server_connection: update handshake hashes
		"""
		if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO or self.state == MB_STATE_RETRY_WAIT_CLIENT_HELLO:
			pass
		else:
			print 'get_client_hello: incorrect state'
			return

		for result in self._getMsg(False, ContentType.handshake, HandshakeType.client_hello):
			if result in (0,1):
				#yield result
				pass
			else:
				break
		result, parser = result
		assert isinstance(result, ClientHello)
		client_hello = result

		# send cached client hello to server
		self.clear_tosend_list(True)
		
		# copy for calculating PSK binders
		self.client_connection._pre_client_hello_handshake_hash = self.client_connection._handshake_hash.copy()

		# update hashes
		self.client_connection._handshake_hash.update(parser.bytes)
		self.server_connection._handshake_hash.update(parser.bytes)

		if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO:
			self.client_hello = client_hello
			self.client_hello_parser = parser
		else:
			self.retry_client_hello = client_hello
			self.retry_client_hello_parser = parser
				
		self.settings = mb_get_settings(client_hello, None)
		self.session = mb_get_resumable_session(self.client_hello)
		# we need to set session for client_connection and server_connection
		self.client_connection.session = self.session
		self.server_connection.session = self.session

		# change state
		if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO:
			self.state = MB_STATE_INITIAL_WAIT_SERVER_HELLO
		else:
			self.state = MB_STATE_RETRY_WAIT_SERVER_HELLO

	# the naive version
	def get_client_hello(self):
		"""
		we read client hello from client_connection
		for client_connection: copy _pre_client_hello_handshake_hash, then update handshake hashes
		for server_connection: update handshake hashes
		"""
		if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO or self.state == MB_STATE_RETRY_WAIT_CLIENT_HELLO:
			pass
		else:
			print 'get_client_hello: incorrect state'
			return

		for result in self._getMsg(False, ContentType.handshake, HandshakeType.client_hello):
			if result in (0,1):
				#yield result
				pass
			else:
				break
		result, parser = result
		assert isinstance(result, ClientHello)
		client_hello = result

		# send client hello to server
		self.clear_tosend_list(True)

		# copy for calculating PSK binders
		self.client_connection._pre_client_hello_handshake_hash = self.client_connection._handshake_hash.copy()

		# update hashes
		self.client_connection._handshake_hash.update(parser.bytes)
		self.server_connection._handshake_hash.update(parser.bytes)

		if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO:
			self.client_hello = client_hello
			self.client_hello_parser = parser
		else:
			self.retry_client_hello = client_hello
			self.retry_client_hello_parser = parser
				
		self.settings = mb_get_settings(client_hello, None)
		self.session = mb_get_resumable_session(self.client_hello)
		# we need to set session for client_connection and server_connection
		self.client_connection.session = self.session
		self.server_connection.session = self.session

		# change state
		if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO:
			self.state = MB_STATE_INITIAL_WAIT_SERVER_HELLO
		else:
			self.state = MB_STATE_RETRY_WAIT_SERVER_HELLO
		
	def stateless_mb_handle_hello_retry(self, hello_retry, parser):
		# we received client hello retry request
		# for client_connection, we update hashes, then update hash with hello retry
		# for server_connection, we update hashes, then update hash with hello retry
		if self.state == MB_STATE_RETRY_WAIT_SERVER_HELLO:
			print 'we received client hello retry request at state MB_STATE_RETRY_WAIT_SERVER_HELLO'
			print 'this sould not happen'
		else:
			# we received the first hello retry
			#print 'mb_handle_hello_retry called'
			# change state
			self.state = MB_STATE_RETRY_WAIT_CLIENT_HELLO
						
			# update hashs for server_connection
			# according to how client handles HRR
			client_hello_hash = self.server_connection._handshake_hash.copy()
			prf_name, prf_size = self.server_connection._getPRFParams(hello_retry.cipher_suite)
			self.server_connection._handshake_hash = HandshakeHashes()
			writer = Writer()
			writer.add(HandshakeType.message_hash, 1)
			writer.addVarSeq(client_hello_hash.digest(prf_name), 1, 3)
			self.server_connection._handshake_hash.update(writer.bytes)
			self.server_connection._handshake_hash.update(parser.bytes)

			# we may should update hashes for client_connection
			# find how server handles HRR
			prf_name, prf_size = self.client_connection._getPRFParams(hello_retry.cipher_suite)

			client_hello_hash = self.client_connection._handshake_hash.digest(prf_name)
			self.client_connection._handshake_hash = HandshakeHashes()
			writer = Writer()
			writer.add(HandshakeType.message_hash, 1)
			writer.addVarSeq(client_hello_hash, 1, 3)
			self.client_connection._handshake_hash.update(writer.bytes)
			self.client_connection._handshake_hash.update(parser.bytes)

			self.client_hello_retry_request = hello_retry
			self.hrr_parser = parser

			# we receive client hello and server hello again
			self.stateless_get_client_hello()
			self.stateless_get_server_hello()

	def asymmetric_mb_handle_hello_retry(self, hello_retry, parser):
		# we received client hello retry request
		# for client_connection, we update hashes, then update hash with hello retry
		# for server_connection, we update hashes, then update hash with hello retry
		if self.state == MB_STATE_RETRY_WAIT_SERVER_HELLO:
			print 'we received client hello retry request at state MB_STATE_RETRY_WAIT_SERVER_HELLO'
			print 'this sould not happen'
		else:
			# we received the first hello retry
			print 'mb_handle_hello_retry called'
			# change state
			self.state = MB_STATE_RETRY_WAIT_CLIENT_HELLO
						
			# update hashs for server_connection
			# according to how client handles HRR
			client_hello_hash = self.server_connection._handshake_hash.copy()
			prf_name, prf_size = self.server_connection._getPRFParams(hello_retry.cipher_suite)
			self.server_connection._handshake_hash = HandshakeHashes()
			writer = Writer()
			writer.add(HandshakeType.message_hash, 1)
			writer.addVarSeq(client_hello_hash.digest(prf_name), 1, 3)
			self.server_connection._handshake_hash.update(writer.bytes)
			self.server_connection._handshake_hash.update(parser.bytes)

			# we may should update hashes for client_connection
			# find how server handles HRR
			prf_name, prf_size = self.client_connection._getPRFParams(hello_retry.cipher_suite)

			client_hello_hash = self.client_connection._handshake_hash.digest(prf_name)
			self.client_connection._handshake_hash = HandshakeHashes()
			writer = Writer()
			writer.add(HandshakeType.message_hash, 1)
			writer.addVarSeq(client_hello_hash, 1, 3)
			self.client_connection._handshake_hash.update(writer.bytes)
			self.client_connection._handshake_hash.update(parser.bytes)

			self.client_hello_retry_request = hello_retry
			self.hrr_parser = parser

			# we store the public ec keys to files
			client_addr, tmp = self.client_sock.getpeername()
			server_addr, tmp = self.server_sock.getpeername()
			x25519_filename = client_addr + server_addr + '.x25519.pubkey'
			secp256r1_filename = client_addr + server_addr + '.secp256r1.pubkey'
			secp384r1_filename = client_addr + server_addr + '.secp374r1.pubkey'
			secp521r1_filename = client_addr + server_addr + '.secp521r1.pubkey'
			client_key_shares = self.client_hello.getExtension(ExtensionType.key_share)
			for entry in client_key_shares.client_shares:
				if entry.group == GroupName.x25519:
					fout = open(x25519_filename, 'w')
					fout.write(entry.key_exchange)
					fout.close()
				elif entry.group == GroupName.secp256r1:
					fout = open(secp256r1_filename, 'w')
					fout.write(entry.key_exchange)
					fout.close()
				elif entry.group == GroupName.secp384r1:
					fout = open(secp384r1_filename, 'w')
					fout.write(entry.key_exchange)
					fout.close()
				elif entry.group == GroupName.secp521r1:
					fout = open(secp521r1_filename, 'w')
					fout.write(entry.key_exchange)
					fout.close()
				else:
					print 'asymmetric_handle_hello_retry: unexpected ec group'
			
			# we receive client hello and server hello again
			self.asymmetric_get_client_hello()
			self.asymmetric_get_server_hello()

	def mb_handle_hello_retry(self, hello_retry, parser):
		# we received client hello retry request
		# for client_connection, we update hashes, then update hash with hello retry
		# for server_connection, we update hashes, then update hash with hello retry
		if self.state == MB_STATE_RETRY_WAIT_SERVER_HELLO:
			print 'we received client hello retry request at state MB_STATE_RETRY_WAIT_SERVER_HELLO'
			print 'this sould not happen'
		else:
			# we received the first hello retry
			print 'mb_handle_hello_retry called'
			# change state
			self.state = MB_STATE_RETRY_WAIT_CLIENT_HELLO
						
			# update hashs for server_connection
			# according to how client handles HRR
			client_hello_hash = self.server_connection._handshake_hash.copy()
			prf_name, prf_size = self.server_connection._getPRFParams(hello_retry.cipher_suite)
			self.server_connection._handshake_hash = HandshakeHashes()
			writer = Writer()
			writer.add(HandshakeType.message_hash, 1)
			writer.addVarSeq(client_hello_hash.digest(prf_name), 1, 3)
			self.server_connection._handshake_hash.update(writer.bytes)
			self.server_connection._handshake_hash.update(parser.bytes)

			# we may should update hashes for client_connection
			# find how server handles HRR
			prf_name, prf_size = self.client_connection._getPRFParams(hello_retry.cipher_suite)

			client_hello_hash = self.client_connection._handshake_hash.digest(prf_name)
			self.client_connection._handshake_hash = HandshakeHashes()
			writer = Writer()
			writer.add(HandshakeType.message_hash, 1)
			writer.addVarSeq(client_hello_hash, 1, 3)
			self.client_connection._handshake_hash.update(writer.bytes)
			self.client_connection._handshake_hash.update(parser.bytes)

			self.client_hello_retry_request = hello_retry
			self.hrr_parser = parser

			# we receive client hello and server hello again
			self.get_client_hello()
			self.get_server_hello()

	def check_server_hello(self, server_hello, real_version):
		if self.retry_client_hello:
			client_hello = self.retry_client_hello
		else:
			client_hello = self.client_hello

		# check server hello
		if self.client_hello_retry_request and self.client_hello_retry_request.cipher_suite != server_hello.cipher_suite:
			print 'hello_retry.cipher_suit != server_hello.cipher_suit'
			print 'this should not happen'
			return False

		self.settings.minVersion = real_version
		self.settings.maxVersion = real_version

		cipherSuites = CipherSuite.filterForVersion(self.client_hello.cipher_suites, minVersion=real_version, maxVersion=real_version)
		if server_hello.cipher_suite not in cipherSuites:
			print 'server_hello.cipher_suite not in cipherSuites'
			print 'this should not happen'
			return False

		if server_hello.certificate_type not in self.client_hello.certificate_types:
			print 'server_hello.certificate_type not in self.client_hello.certificate_types'
			print 'this should not happen'
			return False

		if server_hello.compression_method != 0:
			print 'server_hello.compression_method != 0'
			print 'this should not happen'
			return False
					
		if server_hello.tackExt:
			print 'server_hello.tackExt set'
			if not self.client_hello.tack:
				print 'not self.client_hello.tack'
				print 'this should not happen'
				return False
			if not self.client_hello.tackExt.verifySignatures():
				print 'not self.client_hello.tackExt.verifySignatures()'
				print 'this should not happen'
				return False

		if server_hello.next_protos and not self.client_hello.supports_npn:
			print 'server_hello.next_protos and not self.client_hello.supports_npn'
			print 'this should not happen'
			return False

		if not server_hello.getExtension(ExtensionType.extended_master_secret) and self.settings.requireExtendedMasterSecret:
			print 'server_hello has no extended_master_secret extension and settings require extended master secret'
			print 'this should not happen'
			return False

		aplnExt = server_hello.getExtension(ExtensionType.alpn)
		if aplnExt:
			if not alpnExt.protocol_names or len(alpnExt.protocol_names) != 1:
				print 'alpnExt error'
				print 'this should not happen'
				return False

			clntAlpnExt = client_hello.getExtension(ExtensionType.alpn)
			if not clntAlpnExt:
				print 'client hello does not have application protocol extension'
				print 'this should happen'
				return False
			if alpnExt.protocol_names[0] not in clntAlpnExt.protocol_names:
				print 'application protocol name does not match'
				print 'this should not happen'
				return False
		return True

	# the stateless version
	def stateless_get_server_hello(self):
		"""
		we server hello from server_connection
		we may receive hello retry at state initial wait server hello
		we should not receive hello retry at state retry wait server hello
		"""

		if self.state == MB_STATE_INITIAL_WAIT_SERVER_HELLO or self.state == MB_STATE_RETRY_WAIT_SERVER_HELLO:
			pass
		else:
			print 'get_server_hello: incorrect state'
			return
		
		for result in self._getMsg(True, ContentType.handshake, HandshakeType.server_hello):
			if result in (0,1):
				pass
			else:
				break
		result, parser = result
		assert isinstance(result, ServerHello)
		unknown_record = result

		# send cached server hello or hello retry to client
		self.clear_tosend_list(False)

		hello_retry = None
		server_hello = None
		ext = unknown_record.getExtension(ExtensionType.supported_versions)
		if ext.version > (3, 3):
			pass
		else:
			print 'get_server_hello: unexpected version'

		if unknown_record.random == TLS_1_3_HRR and ext and ext.version > (3, 3):
			hello_retry = unknown_record
		else:
			server_hello = unknown_record

		if server_hello:
			# we received server hello
			# get server hello version
			real_version = server_hello.server_version
			if print_debug_info:
				print 'real_version is:'
				print real_version

			if server_hello.server_version >= (3, 3):
				ext = server_hello.getExtension(ExtensionType.supported_versions)
				if ext:
					real_version = ext.version
					if print_debug_info:
						print 'real_version reset'
						print real_version

			self.server_connection.version = real_version
			self.client_connection.version = real_version
			# check server hello
			if self.check_server_hello(server_hello, real_version):
				if self.state == MB_STATE_INITIAL_WAIT_SERVER_HELLO:
					self.server_hello = server_hello
					self.server_hello_parser = parser
				else:
					self.retry_server_hello = server_hello
					self.retry_server_hello_parser = parser

				# we are about to do key generation
				self.stateless_mb_cal_ec_priv_key_from_server_hello(server_hello)
				#self.mb_cal_ec_priv_key_from_server_hello(server_hello)
				#self.asymmetric_mb_cal_ec_priv_key_from_server_hello(server_hello)
			else:
				print 'check server hello failed'
		else:
			self.stateless_mb_handle_hello_retry(hello_retry, parser)

	# the asymmetric version
	def asymmetric_get_server_hello(self):
		"""
		we server hello from server_connection
		we may receive hello retry at state initial wait server hello
		we should not receive hello retry at state retry wait server hello
		"""

		if self.state == MB_STATE_INITIAL_WAIT_SERVER_HELLO or self.state == MB_STATE_RETRY_WAIT_SERVER_HELLO:
			pass
		else:
			print 'get_server_hello: incorrect state'
			return
		
		for result in self._getMsg(True, ContentType.handshake, HandshakeType.server_hello):
			if result in (0,1):
				pass
			else:
				break
		result, parser = result
		assert isinstance(result, ServerHello)
		unknown_record = result

		# send server hello or hello retry request to client
		self.clear_tosend_list(False)

		hello_retry = None
		server_hello = None
		ext = unknown_record.getExtension(ExtensionType.supported_versions)
		if ext.version > (3, 3):
			pass
		else:
			print 'get_server_hello: unexpected version'

		if unknown_record.random == TLS_1_3_HRR and ext and ext.version > (3, 3):
			hello_retry = unknown_record
		else:
			server_hello = unknown_record

		if server_hello:
			# we received server hello
			# get server hello version
			real_version = server_hello.server_version
			if print_debug_info:
				print 'real_version is:'
				print real_version

			if server_hello.server_version >= (3, 3):
				ext = server_hello.getExtension(ExtensionType.supported_versions)
				if ext:
					real_version = ext.version
					if print_debug_info:
						print 'real_version reset'
						print real_version

			self.server_connection.version = real_version
			self.client_connection.version = real_version
			# check server hello
			if self.check_server_hello(server_hello, real_version):
				if self.state == MB_STATE_INITIAL_WAIT_SERVER_HELLO:
					self.server_hello = server_hello
					self.server_hello_parser = parser
				else:
					self.retry_server_hello = server_hello
					self.retry_server_hello_parser = parser

				# we are about to do key generation
				#self.mb_cal_ec_priv_key_from_server_hello(server_hello)
				self.asymmetric_mb_cal_ec_priv_key_from_server_hello(server_hello)
			else:
				print 'check server hello failed'
		else:
			self.asymmetric_mb_handle_hello_retry(hello_retry, parser)

	def get_server_hello(self):
		"""
		we server hello from server_connection
		we may receive hello retry at state initial wait server hello
		we should not receive hello retry at state retry wait server hello
		"""

		if self.state == MB_STATE_INITIAL_WAIT_SERVER_HELLO or self.state == MB_STATE_RETRY_WAIT_SERVER_HELLO:
			pass
		else:
			print 'get_server_hello: incorrect state'
			return
		
		for result in self._getMsg(True, ContentType.handshake, HandshakeType.server_hello):
			if result in (0,1):
				pass
			else:
				break
		result, parser = result
		assert isinstance(result, ServerHello)
		unknown_record = result

		# send server hello or HRR to client
		self.clear_tosend_list(False)

		hello_retry = None
		server_hello = None
		ext = unknown_record.getExtension(ExtensionType.supported_versions)
		if ext.version > (3, 3):
			pass
		else:
			print 'get_server_hello: unexpected version'

		if unknown_record.random == TLS_1_3_HRR and ext and ext.version > (3, 3):
			hello_retry = unknown_record
		else:
			server_hello = unknown_record

		if server_hello:
			# we received server hello
			# get server hello version
			real_version = server_hello.server_version
			if print_debug_info:
				print 'real_version is:'
				print real_version

			if server_hello.server_version >= (3, 3):
				ext = server_hello.getExtension(ExtensionType.supported_versions)
				if ext:
					real_version = ext.version
					if print_debug_info:
						print 'real_version reset'
						print real_version

			self.server_connection.version = real_version
			self.client_connection.version = real_version
			# check server hello
			if self.check_server_hello(server_hello, real_version):
				if self.state == MB_STATE_INITIAL_WAIT_SERVER_HELLO:
					self.server_hello = server_hello
					self.server_hello_parser = parser
				else:
					self.retry_server_hello = server_hello
					self.retry_server_hello_parser = parser

				# we are about to do key generation
				self.mb_cal_ec_priv_key_from_server_hello(server_hello)
			else:
				print 'check server hello failed'
		else:
			self.mb_handle_hello_retry(hello_retry, parser)
		
	

	# we need to implement our own getMsg function
	# this function can be called to:
	#   get client hello from client_connection
	#   get server_hello from server_connection
	#   get encrypted extensions from server_connection
	#   get certificate from server_connection
	#   get certificate verify from server_connection
	#   get finished from server_connection and client_connection
	# handshake hashes for connection are not automatically updated, except for new session ticket
	# for handshake messages, we yield for example (client_hello, parser),
	def _getMsg(self, from_server, expectedType, secondaryType=None, constructorType=None):
		if from_server:
			connection = self.server_connection
		else:
			connection = self.client_connection

		try:
			if not isinstance(expectedType, tuple):
				expectedType = (expectedType,)


			#Spin in a loop, until we've got a non-empty record of a type we
			#expect.  The loop will be repeated if:
			#  - we receive a renegotiation attempt; we send no_renegotiation,
			#    then try again
			#  - we receive an empty application-data fragment; we try again
			while 1:
				for result in self._getNextRecord(from_server):# we call our own _getNextRecord function here
					if result in (0,1):
						yield result
					else:
						break
				recordHeader, p = result

				# the msg is already plaintext, we ahve sent the cipher text to the other party
				# if this is a CCS message in TLS 1.3, sanity check and
				# continue
				if connection.version > (3, 3) and \
						ContentType.handshake in expectedType and \
						recordHeader.type == ContentType.change_cipher_spec:
					# ccs = ChangeCipherSpec().parse(p)
					# if ccs.type != 1:
					#     for result in self._sendError(
					#             AlertDescription.unexpected_message,
					#             "Invalid CCS message received"):
					#         yield result
					# ignore the message
					continue

				#If we received an unexpected record type...
				if recordHeader.type not in expectedType:
					print 'getMsg: recordHeader.type not in expectedType'
					#If we received an alert...
					if recordHeader.type == ContentType.alert:
						if print_debug_info:
							print 'getMsg: received alert'
							print p.bytes
						

					#If we received a renegotiation attempt...
					if recordHeader.type == ContentType.handshake:
						print 'renegotiation attempt'

					yield 0
						

				#If this is an empty application-data fragment, try again
				if recordHeader.type == ContentType.application_data:
					if p.index == len(p.bytes):
						yield 0 # if we received 0-length application data
						#continue

				break

			# we've got a non-empty record of a type we expect. 

			#Parse based on content_type
			if recordHeader.type == ContentType.change_cipher_spec:
				yield (ChangeCipherSpec().parse(p), p)
			elif recordHeader.type == ContentType.alert:
				yield (Alert().parse(p), p)
			elif recordHeader.type == ContentType.application_data:
				# if from_server:
				#     print 'getMsg: received application data from server_connection:'
				#     print p.bytes
				# else:
				#     print 'getMsg: received application data from client_connection:'
				#     print p.bytes
				yield (ApplicationData().parse(p), p)
			elif recordHeader.type == ContentType.handshake:
				#Convert secondaryType to tuple, if it isn't already
				if not isinstance(secondaryType, tuple):
					secondaryType = (secondaryType,)

				#If it's a handshake message, check handshake header
				if recordHeader.ssl2:
					print 'recordHeader.ssl2: this should not happen'
					subType = p.get(1)
					if subType != HandshakeType.client_hello:
						# for result in self._sendError(\
						#         AlertDescription.unexpected_message,
						#         "Can only handle SSLv2 ClientHello messages"):
						#     yield result
						yield 0
					if HandshakeType.client_hello not in secondaryType:
						# for result in self._sendError(\
						#         AlertDescription.unexpected_message):
						#     yield result
						yield 0
					subType = HandshakeType.client_hello
				else:
					subType = p.get(1)
					if subType not in secondaryType:
						print 'subtype not in sedondaryType'
						# exp = to_str_delimiter(HandshakeType.toStr(i) for i in
						#                        secondaryType)
						# rec = HandshakeType.toStr(subType)
						# for result in self._sendError(AlertDescription
						#                               .unexpected_message,
						#                               "Expecting {0}, got {1}"
						#                               .format(exp, rec)):
						#     yield result
						yield 0
				
				# maybe we should update hashes outside
				# #Update handshake hashes
				# connection._handshake_hash.update(p.bytes)

				#Parse based on handshake type
				if subType == HandshakeType.client_hello:
					yield (ClientHello(recordHeader.ssl2).parse(p), p)
				elif subType == HandshakeType.server_hello:
					yield (ServerHello().parse(p), p)
				elif subType == HandshakeType.certificate:
					yield (Certificate(constructorType, connection.version).parse(p), p)
				elif subType == HandshakeType.certificate_request:
					yield (CertificateRequest(connection.version).parse(p), p)
				elif subType == HandshakeType.certificate_verify:
					yield (CertificateVerify(connection.version).parse(p), p)
				elif subType == HandshakeType.server_key_exchange:
					yield (ServerKeyExchange(constructorType,
											connection.version).parse(p), p)
				elif subType == HandshakeType.server_hello_done:
					yield (ServerHelloDone().parse(p), p)
				elif subType == HandshakeType.client_key_exchange:
					yield (ClientKeyExchange(constructorType, \
											connection.version).parse(p), p)
				elif subType == HandshakeType.finished:
					yield (Finished(connection.version, constructorType).parse(p), p)
				elif subType == HandshakeType.next_protocol:
					yield (NextProtocol().parse(p), p)
				elif subType == HandshakeType.encrypted_extensions:
					yield (EncryptedExtensions().parse(p), p)
				elif subType == HandshakeType.new_session_ticket:
					# update hashes
					self.client_connection._handshake_hash.update(p.bytes)
					self.server_connection._handshake_hash.update(p.bytes)
					#print_new_session_ticket(NewSessionTicket().parse(p))
					ticket = NewSessionTicket().parse(p)
					if print_debug_info:
						print_new_session_ticket(ticket)
					yield (ticket, p)
				else:
					raise AssertionError()

		#If an exception was raised by a Parser or Message instance:
		except SyntaxError as e:
			print 'an exception was raised by a Parser or Message instance'
			print formatExceptionTrace(e)
			yield 0
			# for result in self._sendError(AlertDescription.decode_error,
			#                              formatExceptionTrace(e)):
			#     yield result
	
	def server_connection_handle_server_hello(self, serverHello, parser):
		# mimic _clientTLS13Handshake

		# update hashes
		self.server_connection._handshake_hash.update(parser.bytes)

		# we have client and server hello in TLS 1.3 so we have the necessary
		# key shares to derive the handshake receive key

		# we need to set settings correctly
		settings = self.settings
		# we need to set session correctly
		session = self.session
		if self.retry_client_hello:
			clientHello = self.retry_client_hello
		else:
			clientHello = self.client_hello

		srKex = serverHello.getExtension(ExtensionType.key_share).server_share
		cl_key_share_ex = clientHello.getExtension(ExtensionType.key_share)
		cl_kex = next((i for i in cl_key_share_ex.client_shares
					   if i.group == srKex.group), None)
		if cl_kex is None:
			print 'server_connection_handle_server_hello: server selected not advertised group'
			print 'this should not happen'
			raise TLSIllegalParameterException("Server selected not advertised"
											   " group.")
		kex = self.server_connection._getKEX(srKex.group, self.server_connection.version)

		Z = kex.calc_shared_key(self.mb_ec_private_key, srKex.key_exchange)

		if print_debug_info:
			if srKex.group == GroupName.x25519:
				print 'server selected x25519'
			elif srKex.group == GroupName.secp256r1:
				print 'server selected secp256r1'
			elif srKex.group == GroupName.secp384r1:
				print 'server selected secp384r1'
			elif srKex.group == GroupName.secp521r1:
				print 'server selected secp521r1'
			else:
				print 'server selected unexpected curve'
			print 'server_connection_handle_server_hello: Z is:'
			print binascii.hexlify(Z)

		prfName, prf_size = self.server_connection._getPRFParams(serverHello.cipher_suite)

		# if server agreed to perform resumption, find the matching secret key
		srPSK = serverHello.getExtension(ExtensionType.pre_shared_key)
		self.resuming = False
		if srPSK:
			print 'server hello has psk extension'
			clPSK = clientHello.getExtension(ExtensionType.pre_shared_key)
			ident = clPSK.identities[srPSK.selected]
			psk = [i[1] for i in settings.pskConfigs if i[0] == ident.identity]
			if psk:
				psk = psk[0]
			else:
				self.resuming = True
				psk = HandshakeHelpers.calc_res_binder_psk(
					ident, session.resumptionMasterSecret,
					session.tickets)
		else:
			print 'server hello does not have psk extension'
			psk = bytearray(prf_size)

		secret = bytearray(prf_size)
		# Early Secret
		secret = secureHMAC(secret, psk, prfName)

		if print_debug_info:
			print 'prf name is: ' + prfName
			print 'prf size is: '
			print prf_size
			print 'cipher suite is: '
			print serverHello.cipher_suite
			print 'early secret is:'
			print binascii.hexlify(secret)

		# Handshake Secret
		secret = derive_secret(secret, bytearray(b'derived'),
							   None, prfName)
		secret = secureHMAC(secret, Z, prfName)

		if print_debug_info:
			print 'secret now is:'
			print binascii.hexlify(secret)
			print 'server_connection handshake hash is:'

		sr_handshake_traffic_secret = derive_secret(secret,
													bytearray(b's hs traffic'),
													self.server_connection._handshake_hash,
													prfName)
		cl_handshake_traffic_secret = derive_secret(secret,
													bytearray(b'c hs traffic'),
													self.server_connection._handshake_hash,
													prfName)

		if print_debug_info:
			print 'sr_handshake_traffic_secret is:'
			print binascii.hexlify(sr_handshake_traffic_secret)
			print 'cl_handshake_traffic_secret is:'
			print binascii.hexlify(cl_handshake_traffic_secret)

		# prepare for reading encrypted messages
		self.server_connection._recordLayer.calcTLS1_3PendingState(
			serverHello.cipher_suite,
			cl_handshake_traffic_secret,
			sr_handshake_traffic_secret,
			settings.cipherImplementations)

		self.server_connection._changeReadState()
		return (secret, cl_handshake_traffic_secret, sr_handshake_traffic_secret, prfName, prf_size)

	# we received decrypted ecnrypted extensions from server_connection
	# update hashes
	# encrypted_extensions is of type EncryptedExtensions
	def server_connection_handle_encrypted_extensions(self, encrypted_extensions):
		self.server_connection._handshake_hash.update(self.encrypted_extensions_parser.bytes)

	# we received decrypted certificate from server_connection
	def server_connection_handle_certificate(self, certificate):
		self.server_connection._handshake_hash.update(self.certificate_parser.bytes)

	# we received decrypted certificate verify from server_connection
	def server_connection_handle_certificate_verify(self, certificate_verify):
		self.server_connection._handshake_hash.update(self.certificate_verify_parser.bytes)

	# we received decrypted finished from server_connection
	def server_connection_handle_server_finished(self, finished):
		self.server_connection._handshake_hash.update(self.server_finished_parser.bytes)
		server_finish_hs = self.server_connection._handshake_hash.copy()
		self.server_connection._changeWriteState()
		return server_finish_hs

	# we received decrypted finished from client_connection
	def server_connection_handle_client_finished(self, finished, secret, prf_size, prfName, server_finish_hs, certificate):
		self.server_connection._handshake_hash.update(self.client_finished_parser.bytes)
		# Master secret
		secret = derive_secret(secret, bytearray(b'derived'), None, prfName)
		secret = secureHMAC(secret, bytearray(prf_size), prfName)

		cl_app_traffic = derive_secret(secret, bytearray(b'c ap traffic'),
									   server_finish_hs, prfName)
		sr_app_traffic = derive_secret(secret, bytearray(b's ap traffic'),
									   server_finish_hs, prfName)
		exporter_master_secret = derive_secret(secret,
											   bytearray(b'exp master'),
											   server_finish_hs, prfName)

		settings = self.settings
		if self.retry_server_hello:
			serverHello = self.retry_server_hello
		else:
			serverHello = self.server_hello
		
		self.server_connection._recordLayer.calcTLS1_3PendingState(
			serverHello.cipher_suite,
			cl_app_traffic,
			sr_app_traffic,
			settings.cipherImplementations)
		self.server_connection._changeReadState()
		self.server_connection._changeWriteState()

		resumption_master_secret = derive_secret(secret,
												 bytearray(b'res master'),
												 self.server_connection._handshake_hash, prfName)

		self.server_connection.session = Session()
		self.server_connection.extendedMasterSecret = True

		if self.retry_client_hello:
			clientHello = self.retry_client_hello
		else:
			clientHello = self.client_hello

		serverName = None
		if clientHello.server_name:
			serverName = clientHello.server_name.decode("utf-8")

		appProto = None
		alpnExt = self.encrypted_extensions.getExtension(ExtensionType.alpn)
		if alpnExt:
			appProto = alpnExt.protocol_names[0]

		self.server_connection.session.create(secret,
							bytearray(b''),  # no session_id in TLS 1.3
							serverHello.cipher_suite,
							None,  # no SRP
							None,  # no client cert chain
							certificate.cert_chain if certificate else None,
							None,  # no TACK
							False,  # no TACK in hello
							serverName,
							encryptThenMAC=False,  # all ciphers are AEAD
							extendedMasterSecret=True,  # all TLS1.3 are EMS
							appProto=appProto,
							cl_app_secret=cl_app_traffic,
							sr_app_secret=sr_app_traffic,
							exporterMasterSecret=exporter_master_secret,
							resumptionMasterSecret=resumption_master_secret,
							# NOTE it must be a reference, not a copy!
							tickets=self.server_connection.tickets)

		self.server_connection._handshakeDone(self.resuming)
		self._serverRandom = serverHello.random
		self._clientRandom = clientHello.random

		# print traffic keys
		if print_debug_info:
			print 'server_connection_handle_client_finished print begin:'
			print 'cl_app_traffic is:'
			print binascii.hexlify(cl_app_traffic)
			print 'sr_app_traffic is:'
			print binascii.hexlify(sr_app_traffic)
			print 'exporter_master_secret is:'
			print binascii.hexlify(exporter_master_secret)
			print 'resumption_master_secret is:'
			print binascii.hexlify(resumption_master_secret)
			print 'server_connection_handle_client_finished print end'

	# needs to figure out settings, session and session cache
	
	def client_connection_handle_server_hello(self, server_hello, parser):
		"""
		mimic TLS 1.3 server to to handle server_hello for client_connection
		server_hello is of type ServerHello
		"""
		connection = self.client_connection
		if self.retry_client_hello:
			clientHello = self.retry_client_hello
		else:
			clientHello = self.client_hello

		settings = self.settings

		if clientHello.session_id and self.sessionCache:
			# we set self.session here
			# set it to None for now
			self.session = None
		
		if self.session:
			# session resumption

			pass # for now
		else:
			# we are not doing session resumption
			# get cipher suit
			cipherSuite = server_hello.cipher_suite
			# mimic _serverTLS13Handshake
			# update handshake hashes
			connection._handshake_hash.update(parser.bytes)
			# calculate ECDH key
			prf_name, prf_size = connection._getPRFParams(cipherSuite)
			secret = bytearray(prf_size)
			share = clientHello.getExtension(ExtensionType.key_share)
			share_ids = [i.group for i in share.client_shares]
			# we read selected group from server hello
			selected_group = server_hello.getExtension(ExtensionType.key_share).server_share.group
			cl_key_share = next(i for i in share.client_shares if i.group == selected_group)
			
			# we read psk from server hello
			# if server agreed to perform resumption, find the matching secret key
			serverHello = server_hello
			srPSK = serverHello.getExtension(ExtensionType.pre_shared_key)
			self.server_psk = srPSK
			resuming = False
			if srPSK:
				print 'server hello has psk extension'
				clPSK = clientHello.getExtension(ExtensionType.pre_shared_key)
				ident = clPSK.identities[srPSK.selected]
				psk = [i[1] for i in settings.pskConfigs if i[0] == ident.identity]
				if psk:
					psk = psk[0]
				else:
					resuming = True
					psk = HandshakeHelpers.calc_res_binder_psk(
						ident, self.session.resumptionMasterSecret,
						self.session.tickets)
			else:
				psk = bytearray(prf_size)

			psks = clientHello.getExtension(ExtensionType.pre_shared_key)
			psk_types = clientHello.getExtension(ExtensionType.psk_key_exchange_modes)
			

			if psk is None:
				psk = bytearray(prf_size)

			kex = connection._getKEX(selected_group, self.client_connection.version)
			key_share = server_hello.getExtension(ExtensionType.key_share).server_share# we read key share form server hello
			Z = kex.calc_shared_key(self.mb_ec_private_key, key_share.key_exchange) # calculate ec key
			# Early secret
			secret = secureHMAC(secret, psk, prf_name)
			# Handshake Secret
			secret = derive_secret(secret, bytearray(b'derived'), None, prf_name)
			secret = secureHMAC(secret, Z, prf_name)

			sr_handshake_traffic_secret = derive_secret(secret,
														bytearray(b's hs traffic'),
														connection._handshake_hash,
														prf_name)
			cl_handshake_traffic_secret = derive_secret(secret,
														bytearray(b'c hs traffic'),
														connection._handshake_hash,
														prf_name)
			connection._recordLayer.calcTLS1_3PendingState(
				cipherSuite,
				cl_handshake_traffic_secret,
				sr_handshake_traffic_secret,
				settings.cipherImplementations)

			connection._changeWriteState()
			# wait to receive encrypted extensions
			self.state = MB_STATE_WAIT_ENCRYPTED_EXTENSIONS

			return (secret, prf_name, prf_size)

	# we received decrypted encrypted extensions from server_connection
	# update hashes for client_connection
	# encrypted_extensions is of type EncryptedExtensions
	def client_connection_handle_encrypted_extensions(self, encrypted_extensions):
		self.client_connection._handshake_hash.update(encrypted_extensions.write())

	# we received decrypted certificate from server_connection
	# update hashes for client_connection
	# certificate is of type Certificate
	def client_connection_handle_certificate(self, certificate):
		self.client_connection._handshake_hash.update(certificate.write())
	
	# we received decrypted certificate verify from server_connection
	# update hashes for client connection
	# certificate_verify is of type CertificateVerify
	def client_connection_handle_certificate_verify(self, certificate_verify, prf_name):
		self.client_connection._handshake_hash.digest(prf_name)
		# maybe we do not need the above
		self.client_connection._handshake_hash.update(certificate_verify.write())

	# we received decrypted finished from server_connection
	# finished is of type Finished
	def client_connection_handle_server_finished(self, finished, secret, prf_name, prf_size):
		settings = self.settings
		self.client_connection._handshake_hash.digest(prf_name)
		# maybe we do not need the above
		self.client_connection._handshake_hash.update(finished.write())

		self.client_connection._changeReadState()

		# Master secret
		secret = derive_secret(secret, bytearray(b'derived'), None, prf_name)
		secret = secureHMAC(secret, bytearray(prf_size), prf_name)

		cl_app_traffic = derive_secret(secret, bytearray(b'c ap traffic'),
									   self.client_connection._handshake_hash, prf_name)
		sr_app_traffic = derive_secret(secret, bytearray(b's ap traffic'),
									   self.client_connection._handshake_hash, prf_name)

		if self.retry_server_hello:
			server_hello = self.retry_server_hello
		else:
			server_hello = self.server_hello
		self.client_connection._recordLayer.calcTLS1_3PendingState(server_hello.cipher_suite,
												 cl_app_traffic,
												 sr_app_traffic,
												 settings
												 .cipherImplementations)

		# as both exporter and resumption master secrets include handshake
		# transcript, we need to derive them early
		exporter_master_secret = derive_secret(secret,
											   bytearray(b'exp master'),
											   self.client_connection._handshake_hash,
											   prf_name)
		return (secret, exporter_master_secret, cl_app_traffic, sr_app_traffic)

	# we received decrypted client finished from client_connection
	# finished is of type Finished
	def client_connection_handle_client_finished(self, finished, secret, cl_app_traffic, sr_app_traffic, exporter_master_secret, prf_name):
		self.client_connection._handshake_hash.digest(prf_name)
		self.client_connection._handshake_hash.update(finished.write())
		resumption_master_secret = derive_secret(secret,
												 bytearray(b'res master'),
												 self.client_connection._handshake_hash,
												 prf_name)
		self.client_connection.session = Session()
		self.client_connection.extendedMasterSecret = True
		server_name = None
		if self.retry_client_hello:
			clientHello = self.retry_client_hello
		else:
			clientHello = self.client_hello
		
		if clientHello.server_name:
			server_name = clientHello.server_name.decode('utf-8')

		
		app_proto = None
		alpnExt = self.encrypted_extensions.getExtension(ExtensionType.alpn)
		if alpnExt:
			app_proto = alpnExt.protocol_names[0]

		if self.retry_server_hello:
			serverHello = self.retry_server_hello
		else:
			serverHello = self.server_hello

		self.client_connection.session.create(secret,
							bytearray(b''),  # no session_id
							serverHello.cipher_suite,
							bytearray(b''),  # no SRP
							None,
							self.server_cert_chain,
							None,
							False,
							server_name,
							encryptThenMAC=False,
							extendedMasterSecret=True,
							appProto=app_proto,
							cl_app_secret=cl_app_traffic,
							sr_app_secret=sr_app_traffic,
							exporterMasterSecret=exporter_master_secret,
							resumptionMasterSecret=resumption_master_secret)

		# switch to application_traffic_secret
		self.client_connection._changeWriteState()
		self.client_connection._changeReadState()
		self.client_connection._handshakeDone(self.resuming)
		
		# print traffic keys
		if print_debug_info:
			print 'client_connection_handle_client_finished print begin:'
			print 'cl_app_traffic is:'
			print binascii.hexlify(cl_app_traffic)
			print 'sr_app_traffic is:'
			print binascii.hexlify(sr_app_traffic)
			print 'exporter_master_secret is:'
			print binascii.hexlify(exporter_master_secret)
			print 'resumption_master_secret is:'
			print binascii.hexlify(resumption_master_secret)
			print 'client_connection_handle_client_finished print end'
	# def client_connection_handle_tickets(self, tickets):
	#     # TODO
	#     pass
	
	# def server_connection_handle_tickets(self, tickets):
	#     # TODO
	#     pass

	# the stateless version
	def stateless_mb_cal_ec_priv_key_from_server_hello(self, server_hello):
		# we calculate ec private key here
		if self.retry_client_hello:
			clientHello = self.retry_client_hello
		else:
			clientHello = self.client_hello
		srKex = server_hello.getExtension(ExtensionType.key_share).server_share
		cl_key_share_ex = clientHello.getExtension(ExtensionType.key_share)
		cl_kex = next((i for i in cl_key_share_ex.client_shares
					   if i.group == srKex.group), None)
		if cl_kex is None:
			print 'server selected not advertised group'
			print 'this should not happen'
			return None
		
		# calculate g^b^a
		g_a_b = cal_g_a_b_for_mb(clientHello.random)
		if srKex.group == GroupName.x25519:
			self.mb_ec_private_key = stateless_gen_private_key('x25519', g_a_b)
		elif srKex.group == GroupName.secp256r1:
			self.mb_ec_private_key = stateless_gen_private_key('secp256r1', g_a_b)
		elif srKex.group == GroupName.secp384r1:
			self.mb_ec_private_key = stateless_gen_private_key('secp384r1', g_a_b)
		elif srKex.group == GroupName.secp521r1:
			self.mb_ec_private_key = stateless_gen_private_key('secp521r1', g_a_b)
		else:
			print 'stateless_mb_cal_ec_private_from_server_hello: unexpected curve name'
	# the asymmetric version
	def asymmetric_mb_cal_ec_priv_key_from_server_hello(self, server_hello):
		# we calculate ec private key here
		if self.retry_client_hello:
			clientHello = self.retry_client_hello
		else:
			clientHello = self.client_hello
		srKex = server_hello.getExtension(ExtensionType.key_share).server_share
		cl_key_share_ex = clientHello.getExtension(ExtensionType.key_share)
		cl_kex = next((i for i in cl_key_share_ex.client_shares
					   if i.group == srKex.group), None)
		if cl_kex is None:
			print 'server selected not advertised group'
			print 'this should not happen'
			return

		client_addr, tmp = self.client_sock.getpeername()
		server_addr, tmp = self.server_sock.getpeername()
		x25519_filename = client_addr + server_addr + '.x25519.pubkey'
		secp256r1_filename = client_addr + server_addr + '.secp256r1.pubkey'
		secp384r1_filename = client_addr + server_addr + '.secp374r1.pubkey'
		secp521r1_filename = client_addr + server_addr + '.secp521r1.pubkey'

		if srKex.group == GroupName.x25519:
			self.curve_name = 'x25519'
			# read previous ec public key
			# bytearray of length 32
			self.prev_pubkey_filename = x25519_filename
			pubkey_file = open(self.prev_pubkey_filename, 'r')
			self.prev_public_key = bytearray(pubkey_file.read())
			pubkey_file.close()
			self.alpha = bytearray(32)
			self.alpha[31] = 2
		elif srKex.group == GroupName.secp256r1:
			self.curve_name = 'secp256r1'
			self.prev_pubkey_filename = secp256r1_filename
			pubkey_file = open(self.prev_pubkey_filename, 'r')
			curve = getCurveByName(self.curve_name)
			self.prev_public_key = decodeX962Point(bytearray(pubkey_file.read()), curve)
			pubkey_file.close()
			self.alpha = long(2)
		elif srKex.group == GroupName.secp384r1:
			self.curve_name = 'secp384r1'
			self.prev_pubkey_filename = secp384r1_filename
			pubkey_file = open(self.prev_pubkey_filename, 'r')
			curve = getCurveByName(self.curve_name)
			self.prev_public_key = decodeX962Point(bytearray(pubkey_file.read()), curve)
			pubkey_file.close()
			self.alpha = long(2)
		elif srKex.group == GroupName.secp521r1:
			self.curve_name = 'secp521r1'
			self.prev_pubkey_filename = secp521r1_filename
			pubkey_file = open(self.prev_pubkey_filename, 'r')
			curve = getCurveByName(self.curve_name)
			self.prev_public_key = decodeX962Point(bytearray(pubkey_file.read()), curve)
			pubkey_file.close()
			self.alpha = long(2)
		else:
			print 'server selected unsupported group'
			print 'this should not happen'
	
		# now calculate ec private key
		self.mb_ec_private_key = gen_private_key_for_middlebox(self.curve_name, self.alpha, self.prev_public_key)
		# now store the public keys to file
		client_key_shares = self.client_hello.getExtension(ExtensionType.key_share)
		for entry in client_key_shares.client_shares:
			if entry.group == GroupName.x25519:
				fout = open(x25519_filename, 'w')
				fout.write(entry.key_exchange)
				fout.close()
			elif entry.group == GroupName.secp256r1:
				fout = open(secp256r1_filename, 'w')
				fout.write(entry.key_exchange)
				fout.close()
			elif entry.group == GroupName.secp384r1:
				fout = open(secp384r1_filename, 'w')
				fout.write(entry.key_exchange)
				fout.close()
			elif entry.group == GroupName.secp521r1:
				fout = open(secp521r1_filename, 'w')
				fout.write(entry.key_exchange)
				fout.close()
			else:
				print 'asymmetric cal ec priv key: unexpected ec group'

	# the naive version
	def mb_cal_ec_priv_key_from_server_hello(self, server_hello):
		# we calculate ec private key here
		if self.retry_client_hello:
			clientHello = self.retry_client_hello
		else:
			clientHello = self.client_hello
		srKex = server_hello.getExtension(ExtensionType.key_share).server_share
		cl_key_share_ex = clientHello.getExtension(ExtensionType.key_share)
		cl_kex = next((i for i in cl_key_share_ex.client_shares
					   if i.group == srKex.group), None)
		if cl_kex is None:
			print 'server selected not advertised group'
			print 'this should not happen'
			return
		
		# for testing
		if srKex.group == GroupName.x25519:
			self.mb_ec_private_key = bytearray(32)
			self.mb_ec_private_key[31] = 2
			self.alpha = bytearray(32)
			self.alpha[31] = 2
			return
		elif srKex.group == GroupName.secp256r1 or srKex.group == GroupName.secp384r1 or srKex.group == GroupName.secp521r1:
			self.mb_ec_private_key = long(2)
			self.alpha = long(2)
			return
		else:
			print 'unexpected group'
			return

		if srKex.group == GroupName.x25519:
			self.curve_name = 'x25519'
			# read previous ec public key
			# bytearray of length 32
			self.prev_pubkey_filename = self.curve_name + '.pubkey'
			pubkey_file = open(self.prev_pubkey_filename, 'r')
			self.prev_public_key = bytearray(pubkey_file.read())
			self.alpha = bytearray(32)
			self.alpha[31] = 2
		elif srKex.group == GroupName.secp256r1:
			self.curve_name = 'secp256r1'
			self.prev_pubkey_filename = self.curve_name + '.pubkey'
			pubkey_file = open(self.prev_pubkey_filename, 'r')
			curve = getCurveByName(self.curve_name)
			self.prev_public_key = decodeX962Point(bytearray(pubkey_file.read()), curve)
			self.alpha = long(2)
		elif srKex.group == GroupName.secp384r1:
			self.curve_name = 'secp384r1'
			self.prev_pubkey_filename = self.curve_name + '.pubkey'
			pubkey_file = open(self.prev_pubkey_filename, 'r')
			curve = getCurveByName(self.curve_name)
			self.prev_public_key = decodeX962Point(bytearray(pubkey_file.read()), curve)
			self.alpha = long(2)
		elif srKex.group == GroupName.secp521r1:
			self.curve_name = 'secp521r1'
			self.prev_pubkey_filename = self.curve_name + '.pubkey'
			pubkey_file = open(self.prev_pubkey_filename, 'r')
			curve = getCurveByName(self.curve_name)
			self.prev_public_key = decodeX962Point(bytearray(pubkey_file.read()), curve)
			self.alpha = long(2)
		else:
			print 'server selected unsupported group'
			print 'this should not happen'
	
		# now calculate ec private key
		self.mb_ec_private_key = gen_private_key_for_middlebox(self.curve_name, self.alpha, self.prev_public_key)

	def mb_handle_certificate_request(self):
		"""
		if server send certificate request, it must follow encrypted extensions
		servers which are authenticating with a PSK MUST NOT send the certificate request
		"""
		pass

	# we need to implement our own read function
	def read(self, from_server, max=None, min=1):
		"""Read some data from the TLS connection.

		This function will block until at least 'min' bytes are
		available (or the connection is closed).

		If an exception is raised, the connection will have been
		automatically closed.

		:type max: int
		:param max: The maximum number of bytes to return.

		:type min: int
		:param min: The minimum number of bytes to return

		:rtype: str
		:returns: A string of no more than 'max' bytes, and no fewer
			than 'min' (unless the connection has been closed, in which
			case fewer than 'min' bytes may be returned).

		:raises socket.error: If a socket error occurs.
		:raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
			without a preceding alert.
		:raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
		"""
		for result in self.readAsync(from_server, max, min):
			pass
		return result

	def read_async(self, from_server):
		if from_server:
			connection = self.server_connection
		else:
			connection = self.client_connection
		
		if connection.version > (3, 3):
			allowedTypes = (ContentType.application_data, ContentType.handshake)
			allowedHsTypes = HandshakeType.new_session_ticket
		else:
			print 'read_async: version is not correct, this should not happen'
			allowedTypes = ContentType.application_data
			allowedHsTypes = None
		if not connection.closed:
			try:
				for result in self._getMsg(from_server, allowedTypes, allowedHsTypes):
					if result in (0, 1):
						return result
					
				if isinstance(result, NewSessionTicket):
					result.time = time.time()
					connection.tickets.append(result)
					return 2

				applicationData = result
				connection._readBuffer += applicationData.write()
				max = len(connection._readBuffer)
				returnBytes = connection._readBuffer[:max]
				connection._readBuffer = connection._readBuffer[max:]
				return bytes(returnBytes)
			except TLSRemoteAlert as alert:
				if alert.description != AlertDescription.close_notify:
					raise
			except TLSAbruptCloseError:
				if not connection.ignoreAbruptClose:
					raise
				else:
					connection._shutdown(True)
			except:
				print 'exception happened'
		else:
			print 'connection is already closed'
			return 3


	def readAsync(self, from_server, max=None, min=1):
		"""Start a read operation on the TLS connection.

		This function returns a generator which behaves similarly to
		read().  Successive invocations of the generator will return 0
		if it is waiting to read from the socket, 1 if it is waiting
		to write to the socket, or a string if the read operation has
		completed.

		:rtype: iterable
		:returns: A generator; see above for details.
		"""
		if from_server:
			connection = self.server_connection
		else:
			connection = self.client_connection
		
		if connection.version > (3, 3):
			allowedTypes = (ContentType.application_data,
							ContentType.handshake)
			allowedHsTypes = HandshakeType.new_session_ticket
		else:
			allowedTypes = ContentType.application_data
			allowedHsTypes = None
		try:
			while len(connection._readBuffer) < min and not connection.closed:
				try:
					# we call our own getMsg function here
					for result in self._getMsg(from_server, allowedTypes,
											   allowedHsTypes):
						if result in (0, 1):
							yield result
					if isinstance(result, NewSessionTicket):
						result.time = time.time()
						connection.tickets.append(result)
						continue
					applicationData = result
					connection._readBuffer += applicationData.write()
				except TLSRemoteAlert as alert:
					if alert.description != AlertDescription.close_notify:
						raise
				except TLSAbruptCloseError:
					if not connection.ignoreAbruptClose:
						raise
					else:
						connection._shutdown(True)

			if max == None:
				max = len(connection._readBuffer)

			returnBytes = connection._readBuffer[:max]
			connection._readBuffer = connection._readBuffer[max:]
			yield bytes(returnBytes)
		except GeneratorExit:
			raise
		except:
			connection._shutdown(False)
			raise

	def middleman_common(self):
		# now ec private key is calculated
		if self.retry_server_hello:
			server_hello = self.retry_server_hello
			parser = self.retry_server_hello_parser
		else:
			server_hello = self.server_hello
			parser = self.server_hello_parser

		server_secret, server_cl_handshake_traffic_secret, server_sr_handshake_traffic_secret, server_prf_name, server_prf_size = self.server_connection_handle_server_hello(server_hello, parser)
		client_secret, client_prf_name, client_prf_size = self.client_connection_handle_server_hello(server_hello, parser)
			
		# now read encrypted extensions
		for result in self._getMsg(True, ContentType.handshake, HandshakeType.encrypted_extensions):
			if result in (0,1):
				#yield result
				pass
			else:
				break
		result, parser = result
		assert isinstance(result, EncryptedExtensions)
		self.encrypted_extensions = result
		self.encrypted_extensions_parser = parser
			
		# send encrypted extensions to client
		self.clear_tosend_list(False)

		if print_debug_info:
			print 'received encrypted extensions is:'
			print self.encrypted_extensions

		self.server_connection_handle_encrypted_extensions(self.encrypted_extensions)
		self.client_connection_handle_encrypted_extensions(self.encrypted_extensions)

		# now read certificate and certificate verify from server_connection
		if not self.server_psk:
			# psk is not used, now read certificate and certificate verify from server_connection
			for result in self._getMsg(True, ContentType.handshake, HandshakeType.certificate, CertificateType.x509):
				if result in (0, 1):
					#yield result
					pass
				else:
					break

			result, parser = result
			assert isinstance(result, Certificate)
			self.certificate = result
			self.certificate_parser = parser

			if print_debug_info:
				print 'received certificate is:'
				print self.certificate

			# send certificate to client
			self.clear_tosend_list(False)

			self.server_connection_handle_certificate(self.certificate)
			self.client_connection_handle_certificate(self.certificate)

			# certificate verify
			for result in self._getMsg(True, ContentType.handshake, HandshakeType.certificate_verify):
				if result in (0, 1):
					#yield result
					pass
				else:
					break

			result, parser = result
			assert isinstance(result, CertificateVerify)
			self.certificate_verify = result
			self.certificate_verify_parser = parser

			if print_debug_info:
				print 'received certificate verify is:'
				print self.certificate_verify

			# send certificate verify to client
			self.clear_tosend_list(False)

			self.server_connection_handle_certificate_verify(self.certificate_verify)
			self.client_connection_handle_certificate_verify(self.certificate_verify, client_prf_name)
			
		# now read finished from server_connection
		for result in self._getMsg(True, ContentType.handshake, HandshakeType.finished, server_prf_size):
			if result in (0, 1):
				#yield result
				pass
			else:
				break
		result, parser = result
		assert isinstance(result, Finished)
		self.server_finished = result
		self.server_finished_parser = parser

		if print_debug_info:
			print 'received server finished is:'
			print_finished(self.server_finished)

		server_finish_hs = self.server_connection_handle_server_finished(self.server_finished)
		client_secret, client_exporter_master_secret, clieint_cl_app_traffic, client_sr_app_traffic = self.client_connection_handle_server_finished(self.server_finished, client_secret, client_prf_name, client_prf_size)

		# send server finished to client
		self.clear_tosend_list(False)
		
		# now read finished from client_connection
		for result in self._getMsg(False, ContentType.handshake, HandshakeType.finished, client_prf_size):
			if result in (0, 1):
				#yield result
				pass
			else:
				break
		result, parser = result
		assert isinstance(result, Finished)
		self.client_finished = result
		self.client_finished_parser = parser

		if print_debug_info:
			print 'received client finished is:'
			print_finished(self.client_finished)

		self.server_connection_handle_client_finished(self.client_finished, server_secret, server_prf_size, server_prf_name, server_finish_hs, self.certificate)
		self.client_connection_handle_client_finished(self.client_finished, client_secret, clieint_cl_app_traffic, client_sr_app_traffic, client_exporter_master_secret, client_prf_name)
			
		# send client finished to server
		self.clear_tosend_list(True)

	# TODO: this function needs modification
	# we use the client socket's peer ip and server socket's peer ip to check if 
	# the previous public key files exist
	# if exist, we generate ec private key for this round, store this round's public key
	# and decrypt traffic
	# if not, we store the public key files, then tare down the connections
	def asymmetric_middleman(self):
		client_addr, tmp = self.client_sock.getpeername()
		server_addr, tmp = self.server_sock.getpeername()
		x25519_filename = client_addr + server_addr + '.x25519.pubkey'
		secp256r1_filename = client_addr + server_addr + '.secp256r1.pubkey'
		secp384r1_filename = client_addr + server_addr + '.secp374r1.pubkey'
		secp521r1_filename = client_addr + server_addr + '.secp521r1.pubkey'
		# check if the files exist
		if os.path.isfile(x25519_filename) or os.path.isfile(secp256r1_filename) or os.path.isfile(secp384r1_filename) or os.path.isfile(secp521r1_filename):
			# we generate ec private key for this connection, store this connection's public key and decrypt traffic
			self.state = MB_STATE_INITIAL_WAIT_CLIENT_HELLO
			# we receive client hello from self.client_connection
			self.asymmetric_get_client_hello()
			print 'the client hello is:'
			print self.client_hello

			self.asymmetric_get_server_hello() # handles client hello retry request
			print 'the server hello is'
			print self.server_hello
			if self.client_hello_retry_request:
				print 'received HRR'
				print self.client_hello_retry_request
				print 'retry client hello is:'
				print self.retry_client_hello
				print 'retry server hello is'
				print self.retry_server_hello
			self.middleman_common()
			self.simple_forward_data(False)
		else:
			# we store the public key files, then tare down the connections
			self.state = MB_STATE_INITIAL_WAIT_CLIENT_HELLO
			# receive client hello from client_connection
			self.get_client_hello() # now self.client_hello is the client hello we got
			client_key_shares = self.client_hello.getExtension(ExtensionType.key_share)
			for entry in client_key_shares.client_shares:
				if entry.group == GroupName.x25519:
					fout = open(x25519_filename, 'w')
					fout.write(entry.key_exchange)
					fout.close()
				elif entry.group == GroupName.secp256r1:
					fout = open(secp256r1_filename, 'w')
					fout.write(entry.key_exchange)
					fout.close()
				elif entry.group == GroupName.secp384r1:
					fout = open(secp384r1_filename, 'w')
					fout.write(entry.key_exchange)
					fout.close()
				elif entry.group == GroupName.secp521r1:
					fout = open(secp521r1_filename, 'w')
					fout.write(entry.key_exchange)
					fout.close()
				else:
					print 'asymmetric middleman: unexpected ec group'

			# close the client socket and server socket
			self.client_sock.close()
			self.server_sock.close()

	def inspection_data(self, data):
		# data is of type byte array
		#print 'inspection_data is called'
		data_len = len(data)
		self.app_data_len += data_len
		if self.app_data_len >= 9637000:
			print 'clean tosend list interval is: ' + str(self.clear_tosend_list_interval)

		if 0 < data_len and data_len <= 0xffff:
			high = (data_len & 0xff00) >> 8
			low = data_len & 0x00ff
			tosend = bytearray()
			tosend.append(high)
			tosend.append(low)
			tosend = tosend + data
			self.inspection_client_sock.sendall(tosend)
			# read reply
			reply = self.inspection_client_sock.recv(1)

	def select_forward_data(self, perform_inspection):
		# now we should be able to read decrypted data from client_connection and server_connection
		# new session ticket is handled in our read function
		print 'simple_forward_data called'

		allowedTypes = (ContentType.application_data, ContentType.handshake, ContentType.alert, ContentType.change_cipher_spec)
		allowedHsTypes = HandshakeType.new_session_ticket
		inputs = [self.client_sock, self.server_sock]

		client_interval = 0
		server_interval = 0
		select_interval = 0
		time_interval = 0
		while inputs:
			lasttime = time.time()
			if self.client_connection.closed:
				print 'middleman: client_connection is closed'
				break
			if self.server_connection.closed:
				print 'middleman: server_connection is closed'
				break

			readable, writable, exceptional = select.select(inputs, [], inputs)
			if print_debug_info:
				for s in readable:
					if s == self.server_sock:
						print 'server_sock in readable'
					if s == self.client_sock:
						print 'client_sock in readable'
			nowtime = time.time()
			select_interval += (nowtime - lasttime)
			#print 'select interval = ' + str(select_interval)

			for s in readable:
				lasttime = time.time()
				for result in self._getMsg(s == self.server_sock, allowedTypes, allowedHsTypes):
					time1 = time.time()
					if result in (0, 1):
						if s == self.client_sock:
							print 'getMsg yield 0 or 1 from client'
						else:
							print 'getMsg yield 0 or 1 from server'
						break
					else:
						result, parser = result
						if isinstance(result, ChangeCipherSpec):
							if s == self.client_sock:
								print 'middleman: received change cipher spec from client'
							else:
								print 'middleman: received ccs from server'
						elif isinstance(result, ApplicationData):
							if print_debug_info:
								if s == self.client_sock:
									print 'middleman: received application data from client'
								else:
									print 'middleman: received application data from server' + str(len(parser.bytes)) + ' bytes'
							#print parser.bytes
							if perform_inspection:
								self.inspection_data(parser.bytes)

						elif isinstance(result, Alert):
							if s == self.client_sock:
								print 'received Alert from client'
							else:
								print 'received alert from server'
							self.client_sock.close()
							self.server_sock.close()
							inputs = []
							# TODO on connection close, we should store session to disk for session resumption
						else:
							if s == self.client_sock:
								print 'middleman: received unexpected record from client'
							else:
								print 'middleman: received unexpected record from server'
						# send cached data to server or server
						self.clear_tosend_list(s == self.client_sock)
						time2 = time.time()
						time_interval += (time2 - time1)
						#print 'time interval = ' + str(time_interval)
						#break
				nowtime = time.time()
				if s == self.client_sock:
					client_interval += (nowtime - lasttime)
				else:
					server_interval += (nowtime - lasttime)
			
			# print 'client interval = ' + str(client_interval)
			# print 'server interval = ' + str(server_interval)

			if len(exceptional) > 0:
				self.client_sock.close()
				self.server_sock.close()
				print 'exception happened, exiting..'
				break

	def simple_forward_data(self, perform_inspection):
		# now we should be able to read decrypted data from client_connection and server_connection
		# new session ticket is handled in our read function
		print 'simple_forward_data called'

		allowedTypes = (ContentType.application_data, ContentType.handshake, ContentType.alert, ContentType.change_cipher_spec)
		allowedHsTypes = HandshakeType.new_session_ticket
		while True:
			if self.client_connection.closed:
				print 'middleman: client_connection is closed'
				break
			if self.server_connection.closed:
				print 'middleman: server_connection is closed'
				break
				
			for result in self._getMsg(False, allowedTypes, allowedHsTypes):
				if result in (0, 1):
					break
				else:
					result, parser = result
					if isinstance(result, ChangeCipherSpec):
						print 'middleman: received change cipher spec from client'
					elif isinstance(result, ApplicationData):
						#print 'middleman: received application data from client'
						#print parser.bytes
						if perform_inspection:
							self.inspection_data(parser.bytes)

					elif isinstance(result, Alert):
						print 'received Alert from client'
						# TODO on connection close, we should store session to disk for session resumption
					else:
						print 'middleman: received unexpected record from client'
					
					# send cached data to server
					self.clear_tosend_list(True)

					break
					

			for result in self._getMsg(True, allowedTypes, allowedHsTypes):
				if result in (0, 1):
					break
				else:
					result, parser = result
					if isinstance(result, ChangeCipherSpec):
						print 'middleman: received change cipher spec from server'
					elif isinstance(result, NewSessionTicket):
						print 'middleman: received new session ticket from server'
					elif isinstance(result, ApplicationData):
						#print 'middleman: received application data from server'
						#print parser.bytes
						if perform_inspection:
							self.inspection_data(parser.bytes)

					elif isinstance(result, Alert):
						print 'middleman: recevied alert from server'
						# TODO on connection close, we should store session to disk for resumption
					else:
						print 'middleman: received unexpected record from server'
					
					# send cached data to client
					self.clear_tosend_list(False)

					break
	def stateless_middleman(self):
		"""
		after the socks 5 proxy is set, this function is called
		"""
		print 'stateless_middleman called'

		self.state = MB_STATE_INITIAL_WAIT_CLIENT_HELLO
		self.stateless_get_client_hello()
		# print 'the client hello is:'
		# print self.client_hello

		self.stateless_get_server_hello() # handles client hello retry request
		# print 'the server hello is:'
		# print self.server_hello
		# if self.client_hello_retry_request:
		# 	print 'received HRR'
		# 	print self.client_hello_retry_request
		# 	print 'retry client hello is:'
		# 	print self.retry_client_hello
		# 	print 'retry server hello is:'
		# 	print self.retry_server_hello
		
		# now ec private key is calculated
		self.middleman_common()
		self.select_forward_data(True)
		#no_accumulate_forward_data(self.client_sock, self.server_sock)

	def naive_middleman(self):
		"""
		after the socks5 proxy is set, this function is called
		"""
		self.state = MB_STATE_INITIAL_WAIT_CLIENT_HELLO
		# we receive client hello from self.client_connection
		self.get_client_hello()
		print 'the client hello is:'
		print self.client_hello

		self.get_server_hello() # handles client hello retry request
		print 'the server hello is'
		print self.server_hello
		if self.client_hello_retry_request:
			print 'received HRR'
			print self.client_hello_retry_request
			print 'retry client hello is:'
			print self.retry_client_hello
			print 'retry server hello is'
			print self.retry_server_hello

		# now ec private key is calculated
		self.middleman_common()
		self.simple_forward_data(False)

def mb_get_settings(client_hello, sever_hello):
	"""
	return constructed handshake settings from client hello and server_hello
	client_hello: input, of type ClientHello
	server_hello: input, of type ServerHello
	"""
	settings = HandshakeSettings()
	settings = settings.validate()
	ext = client_hello.getExtension(ExtensionType.encrypt_then_mac)
	settings.useEncryptThenMAC = (ext != None)
	ext = client_hello.getExtension(ExtensionType.extended_master_secret)
	settings.useExtendedMasterSecret = (ext != None)

	# set minVersion and maxVersion

	# set requireExtendedMasterSecret

	# set resumable session related
	settings.pskConfigs = None # for now

	# set cipherImplementations
	return settings

def mb_get_resumable_session(client_hello):
	"""
	return constructed resumable session from client hello
	client_hello: input, of type ClientHello
	"""
	# read from file and retrun
	# return None for now
	return None

def print_new_session_ticket(ticket):
	print 'ticket_lifetime is:'
	print ticket.ticket_lifetime
	print 'ticket_age_add is:'
	print ticket.ticket_age_add
	print 'ticket nonce is:'
	print ticket.ticket_nonce
	print 'ticket is:'
	print ticket.ticket
	print 'extensions is:'
	print ticket.extensions

def print_finished(finished):
	print 'version is:'
	print finished.version
	print 'verify data is:'
	print binascii.hexlify(finished.verify_data)
	print 'hash length is:'
	print finished.hash_length
