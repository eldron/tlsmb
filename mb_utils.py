from tlslite.handshakesettings import *
from tlslite.messages import *
from tlslite.extensions import *
from tlslite.utils.codec import *
from tlslite import TLSConnection
from tlslite.session import *

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

class MBHandshakeState(object):
    def __init__(self):
        self.client_hello = None
        self.server_hello = None
        self.state = MB_STATE_INITIAL_WAIT_CLIENT_HELLO
        self.client_hello_retry_request = None
        self.retry_client_hello = None
        self.retry_server_hello = None
        self.settings = None
        self.server_connection = None
        self.client_connection = None
        self.session = None
        self.client_sock = None # the socket through which we connected with the real tls 1.3 client
        self.server_sock = None # the socket through which we connected with the tls 1.3 server

    def set_server_sock(sock):
        """
        set the socket through which the middlebox connected with the tls 1.3 server
        also initializes self.server_connection
        """
        self.server_sock = sock
        self.server_connection = TLSConnection(sock)

    def set_client_sock(sock):
        """
        set the socket through which the middlebox connected with the real tls 1.3 client
        also initializes self.client_connection
        """
        self.client_sock = sock
        self.client_sock = TLSConnection(sock)
    
    # we need to implement our own getNextRecordFromSocket function
    # basically copied, remove send msg calls
    def _getNextRecordFromSocket(self, from_server):
        """Read a record, handle errors"""
        if from_server:
            connection = self.server_connection
        else:
            connection = self.client_connection
        
        try:
            # otherwise... read the next record
            # self.connection._recordLayer.recvRecord() should not contain send msg calls
            for result in connection._recordLayer.recvRecord():
                if result in (0, 1):
                    yield result
                else:
                    break
        except TLSUnexpectedMessage:
            # for result in self._sendError(AlertDescription.unexpected_message):
            #     yield result
            print 'TLSUnexpectedMessage exception raised'
            yield 0
        except TLSRecordOverflow:
            # for result in self._sendError(AlertDescription.record_overflow):
            #     yield result
            print 'TLSRecordOverflow raised'
            yield 0
        except TLSIllegalParameterException:
            # for result in self._sendError(AlertDescription.illegal_parameter):
            #     yield result
            print 'TLSIllegalParameterException raised'
            yield 0
        except TLSDecryptionFailed:
            # for result in self._sendError(
            #         AlertDescription.decryption_failed,
            #         "Encrypted data not a multiple of blocksize"):
            #     yield result
            print 'TLSDecryptionFailed raised'
            yield 0
        except TLSBadRecordMAC:
            # for result in self._sendError(
            #         AlertDescription.bad_record_mac,
            #         "MAC failure (or padding failure)"):
            #     yield result
            print 'TLSBadRecordMAC raised'
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
    #Returns next record or next handshake message
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
                yield (header, parser)
            # If it's an SSLv2 ClientHello, we can return it as well, since
            # it's the only ssl2 type we support
            elif header.ssl2:
                yield (header, parser)
            else:
                # other types need to be put into buffers
                connection._defragmenter.add_data(header.type, parser.bytes)


    # we need to implement our own getMsg function
    def getMsg(self, from_server, expectedType, secondaryType=None, constructorType=None):
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

                # we send to the other party
                if from_server:
                    self.client_sock.write(recordHeader.write() + p.bytes)
                else:
                    self.server_sock.write(recordHeader.write() + p.bytes)

                # if this is a CCS message in TLS 1.3, sanity check and
                # continue
                if connection.version > (3, 3) and \
                        ContentType.handshake in expectedType and \
                        recordHeader.type == ContentType.change_cipher_spec:
                    ccs = ChangeCipherSpec().parse(p)
                    if ccs.type != 1:
                        # for result in self._sendError(
                        #         AlertDescription.unexpected_message,
                        #         "Invalid CCS message received"):
                        #     yield result
                        print 'invalid CCS message received'
                        yield 0
                    # ignore the message
                    continue

                #If we received an unexpected record type...
                if recordHeader.type not in expectedType:
                    # we don't need to further process it

                    # #If we received an alert...
                    # if recordHeader.type == ContentType.alert:
                    #     alert = Alert().parse(p)

                    #     #We either received a fatal error, a warning, or a
                    #     #close_notify.  In any case, we're going to close the
                    #     #connection.  In the latter two cases we respond with
                    #     #a close_notify, but ignore any socket errors, since
                    #     #the other side might have already closed the socket.
                    #     if alert.level == AlertLevel.warning or \
                    #        alert.description == AlertDescription.close_notify:

                    #         #If the sendMsg() call fails because the socket has
                    #         #already been closed, we will be forgiving and not
                    #         #report the error nor invalidate the "resumability"
                    #         #of the session.
                    #         try:
                    #             # alertMsg = Alert()
                    #             # alertMsg.create(AlertDescription.close_notify,
                    #             #                 AlertLevel.warning)
                    #             # for result in self._sendMsg(alertMsg):
                    #             #     yield result
                    #             yield 0
                    #         except socket.error:
                    #             pass

                    #         # if alert.description == \
                    #         #        AlertDescription.close_notify:
                    #         #     self._shutdown(True)
                    #         # elif alert.level == AlertLevel.warning:
                    #         #     self._shutdown(False)

                    #     else: #Fatal alert:
                    #         self._shutdown(False)

                    #     #Raise the alert as an exception
                    #     raise TLSRemoteAlert(alert)

                    # #If we received a renegotiation attempt...
                    # if recordHeader.type == ContentType.handshake:
                    #     subType = p.get(1)
                    #     reneg = False
                    #     if self._client:
                    #         if subType == HandshakeType.hello_request:
                    #             reneg = True
                    #     else:
                    #         if subType == HandshakeType.client_hello:
                    #             reneg = True
                    #     # Send no_renegotiation if we're not negotiating
                    #     # a connection now, then try again
                    #     if reneg and self.session:
                    #         alertMsg = Alert()
                    #         alertMsg.create(AlertDescription.no_renegotiation,
                    #                         AlertLevel.warning)
                    #         for result in self._sendMsg(alertMsg):
                    #             yield result
                    #         continue

                    # #Otherwise: this is an unexpected record, but neither an
                    # #alert nor renegotiation
                    # for result in self._sendError(\
                    #         AlertDescription.unexpected_message,
                    #         "received type=%d" % recordHeader.type):
                    #     yield result

                #If this is an empty application-data fragment, try again
                if recordHeader.type == ContentType.application_data:
                    if p.index == len(p.bytes):
                        continue

                break# we've got a non-empty record of a type we expect. 

            #Parse based on content_type
            if recordHeader.type == ContentType.change_cipher_spec:
                yield ChangeCipherSpec().parse(p)
            elif recordHeader.type == ContentType.alert:
                yield Alert().parse(p)
            elif recordHeader.type == ContentType.application_data:
                yield ApplicationData().parse(p)
            elif recordHeader.type == ContentType.handshake:
                #Convert secondaryType to tuple, if it isn't already
                if not isinstance(secondaryType, tuple):
                    secondaryType = (secondaryType,)

                #If it's a handshake message, check handshake header
                if recordHeader.ssl2:
                    subType = p.get(1)
                    if subType != HandshakeType.client_hello:
                        # for result in self._sendError(\
                        #         AlertDescription.unexpected_message,
                        #         "Can only handle SSLv2 ClientHello messages"):
                        #     yield result
                        print 'subtype != client_hello, can only handle SSLv2 ClientHello messages'
                        yield 0
                    if HandshakeType.client_hello not in secondaryType:
                        # for result in self._sendError(\
                        #         AlertDescription.unexpected_message):
                        #     yield result
                        print 'received unexpceted msg: secondary type error'
                        yield 0
                    subType = HandshakeType.client_hello
                else:
                    subType = p.get(1)
                    if subType not in secondaryType:
                        # exp = to_str_delimiter(HandshakeType.toStr(i) for i in
                        #                        secondaryType)
                        # rec = HandshakeType.toStr(subType)
                        # for result in self._sendError(AlertDescription
                        #                               .unexpected_message,
                        #                               "Expecting {0}, got {1}"
                        #                               .format(exp, rec)):
                        #     yield result
                        print 'subtype not in secondaryType'
                        yield 0

                #Update handshake hashes
                #self._handshake_hash.update(p.bytes)
                connection._handshake_hash.update(p.bytes)

                #Parse based on handshake type
                if subType == HandshakeType.client_hello:
                    yield ClientHello(recordHeader.ssl2).parse(p)
                elif subType == HandshakeType.server_hello:
                    yield ServerHello().parse(p)
                elif subType == HandshakeType.certificate:
                    yield Certificate(constructorType, connection.version).parse(p)
                elif subType == HandshakeType.certificate_request:
                    yield CertificateRequest(connection.version).parse(p)
                elif subType == HandshakeType.certificate_verify:
                    yield CertificateVerify(connection.version).parse(p)
                elif subType == HandshakeType.server_key_exchange:
                    yield ServerKeyExchange(constructorType,
                                            connection.version).parse(p)
                elif subType == HandshakeType.server_hello_done:
                    yield ServerHelloDone().parse(p)
                elif subType == HandshakeType.client_key_exchange:
                    yield ClientKeyExchange(constructorType, \
                                            connection.version).parse(p)
                elif subType == HandshakeType.finished:
                    yield Finished(connection.version, constructorType).parse(p)
                elif subType == HandshakeType.next_protocol:
                    yield NextProtocol().parse(p)
                elif subType == HandshakeType.encrypted_extensions:
                    yield EncryptedExtensions().parse(p)
                elif subType == HandshakeType.new_session_ticket:
                    yield NewSessionTicket().parse(p)
                else:
                    raise AssertionError()

        #If an exception was raised by a Parser or Message instance:
        except SyntaxError as e:
            # for result in self._sendError(AlertDescription.decode_error,
            #                              formatExceptionTrace(e)):
            #     yield result
            print 'an exception was raised by a Parser or Message instance'
            yield 0
          
    def mb_handle_server_hello(self):
        settings = self.settings
        session = self.session
        if self.retry_client_hello:
            clientHello = self.retry_client_hello
        else:
            clientHello = self.client_hello

        if self.retry_server_hello:
            serverHello = self.retry_server_hello
        else:
            serverHello = self.server_hello

        # we have client and server hello in TLS 1.3 so we have the necessary
        # key shares to derive the handshake receive key
        srKex = serverHello.getExtension(ExtensionType.key_share).server_share
        cl_key_share_ex = clientHello.getExtension(ExtensionType.key_share)
        cl_kex = next((i for i in cl_key_share_ex.client_shares
                       if i.group == srKex.group), None)
        if cl_kex is None:
            print 'server selected not advertised group'
            print 'this should not happen'
            raise TLSIllegalParameterException("Server selected not advertised"
                                               " group.")
        kex = self.connection._getKEX(srKex.group, self.connection.version)

        Z = kex.calc_shared_key(cl_kex.private, srKex.key_exchange)

        prfName, prf_size = self._getPRFParams(serverHello.cipher_suite)
        # if server agreed to perform resumption, find the matching secret key
        srPSK = serverHello.getExtension(ExtensionType.pre_shared_key)
        resuming = False
        if srPSK:
            clPSK = clientHello.getExtension(ExtensionType.pre_shared_key)
            ident = clPSK.identities[srPSK.selected]
            psk = [i[1] for i in settings.pskConfigs if i[0] == ident.identity]
            if psk:
                psk = psk[0]
            else:
                resuming = True
                psk = HandshakeHelpers.calc_res_binder_psk(
                    ident, session.resumptionMasterSecret,
                    session.tickets)
        else:
            psk = bytearray(prf_size)

        secret = bytearray(prf_size)
        # Early Secret
        secret = secureHMAC(secret, psk, prfName)
        # Handshake Secret
        secret = derive_secret(secret, bytearray(b'derived'),
                               None, prfName)
        secret = secureHMAC(secret, Z, prfName)

        # server handshake traffic secret
        sr_handshake_traffic_secret = derive_secret(secret,
                                                    bytearray(b's hs traffic'),
                                                    self.connection._handshake_hash,
                                                    prfName)
        # client handshake traffic secret
        cl_handshake_traffic_secret = derive_secret(secret,
                                                    bytearray(b'c hs traffic'),
                                                    self.connection._handshake_hash,
                                                    prfName)
        # prepare for reading encrypted messages
        self.connection._recordLayer.calcTLS1_3PendingState(
            serverHello.cipher_suite,
            cl_handshake_traffic_secret,
            sr_handshake_traffic_secret,
            settings.cipherImplementations)

        self.connection._changeReadState()

    def mb_hanlde_encrypted_extensions(self):

    def mb_handle_certificate_request(self):
        """
        if server send certificate request, it must follow encrypted extensions
        servers which are authenticating with a PSK MUST NOT send the certificate request
        """
        pass

    def mb_handle_certificate(self):
        """
        this function is called when PSK is not used
        """
    def mb_handle_certificate_verify(self):
        """
        this function is called when PSK is not used
        """

    def mb_handle_server_finished(self):

    def mb_handle_client_finished(self):

    def mb_handle_application_data(self):

    def handle_record(self, record_data):
        """
        record_data: input, of type bytearray, a complete TLS record raw data
        """
        content_type = ord(record_data[0])
        if content_type == ContentType.handshake:
            client_hello = None
            server_hello = None
            hello_retry = None
            msg_type = ord(record_data[5])
            if msg_type == HandshakeType.client_hello:
                client_hello = mb_set_client_hello(record_data)
            elif msg_type == HandshakeType.server_hello:
                result = mb_set_server_hello(record_data)
                ext = result.getExtension(ExtensionType.supported_versions)
                if ext.version > (3, 3):
                    pass
                else:
                    print 'handle_record: unexpected version'

                if result.random == TLS_1_3_HRR and ext and ext.version > (3, 3):
                    hello_retry = result
                else:
                    server_hello = result
            else:
                print 'handle_record: unexpected handshake type'

            if client_hello != None:
                # we received client hello
                if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO:
                    # we received first client hello
                    if self.connection == None and self.settings == None and self.session == None:
                        self.client_hello = client_hello
                        self.settings = mb_get_settings(client_hello)
                        self.session = mb_get_resumable_session(client_hello)
                        self.connection = TLSConnection(None) # initialized handshake hashes
                        self.connection.sock = None
                        self.connection.session = self.session
                        self.connection._handshake_hash.update(client_hello.write())
                        self.state = MB_STATE_INITIAL_WAIT_SERVER_HELLO
                    else:
                        print 'at state initial wait client hello, connection or settings or session is not None'
                        print 'this should not happen'
                elif self.state == MB_STATE_RETRY_WAIT_CLIENT_HELLO:
                    # we recevied the second client hello
                    if self.connection != None:
                        self.retry_client_hello = client_hello
                        self.settings = mb_get_settings(client_hello)
                        self.session = mb_get_resumable_session(client_hello)
                        self.connection.session = self.session
                        self.connection._handshake_hash.update(client_hello.write())
                        self.state = MB_STATE_RETRY_WAIT_SERVER_HELLO
                    else:
                        print 'we received the second client hello, but connection is None'
                        print 'this should not happen'
                else:
                    print 'handle_record: received client hello at unexpected state'
            elif server_hello != None:
                # we received server_hello
                if self.state == MB_STATE_INITIAL_WAIT_SERVER_HELLO or self.state == MB_STATE_RETRY_WAIT_SERVER_HELLO:
                    # we received the first server hello

                    # get server hello version
                    real_version = server_hello.server_version
                    if server_hello.server_version >= (3, 3):
                        ext = server_hello.getExtension(ExtensionType.supported_versions)
                        if ext:
                            real_version = ext.version
                    self.connection.version = real_version

                    # check server hello
                    check_server_hello_result = True
                    if self.client_hello_retry_request and self.client_hello_retry_request.cipher_suite != server_hello.cipher_suite:
                        print 'hello_retry.cipher_suit != server_hello.cipher_suit'
                        print 'this should not happen'
                        check_server_hello_result = False
                    
                    if real_version < self.settings.minVersion:
                        print 'real_version < settings.minVersion'
                        print 'this should not happen'
                        check_server_hello_result = False

                    if real_version > self.settings.maxVersion:
                        print 'real_version > settings.maxVersion'
                        print 'this should not happen'
                        check_server_hello_result = False

                    cipherSuites = CipherSuite.filterForVersion(self.client_hello.cipher_suites, minVersion=real_version, maxVersion=real_version)
                    if server_hello.cipher_suite not in cipherSuites:
                        print 'server_hello.cipher_suite not in cipherSuites'
                        print 'this should not happen'
                        check_server_hello_result = False

                    if server_hello.certificate_type not in self.client_hello.certificate_types:
                        print 'server_hello.certificate_type not in self.client_hello.certificate_types'
                        print 'this should not happen'
                        check_server_hello_result = False

                    if server_hello.compression_method != 0:
                        print 'server_hello.compression_method != 0'
                        print 'this should not happen'
                        check_server_hello_result = False
                    
                    if server_hello.tackExt:
                        print 'server_hello.tackExt set'
                        if not self.client_hello.tack:
                            print 'not self.client_hello.tack'
                            print 'this should not happen'
                            check_server_hello_result = False
                        if not self.client_hello.tackExt.verifySignatures():
                            print 'not self.client_hello.tackExt.verifySignatures()'
                            print 'this should not happen'
                            check_server_hello_result = False

                    if server_hello.next_protos and not self.client_hello.supports_npn:
                        print 'server_hello.next_protos and not self.client_hello.supports_npn'
                        print 'this should not happen'
                        check_server_hello_result = False

                    if not server_hello.getExtension(ExtensionType.extended_master_secret) and self.settings.requireExtendedMasterSecret:
                        print 'server_hello has no extended_master_secret extension and settings require extended master secret'
                        print 'this should not happen'
                        check_server_hello_result = False

                    aplnExt = server_hello.getExtension(ExtensionType.alpn)
                    if aplnExt:
                        if not alpnExt.protocol_names or len(alpnExt.protocol_names) != 1:
                            print 'alpnExt error'
                            print 'this should not happen'
                            check_server_hello_result = False

                        clntAlpnExt = client_hello.getExtension(ExtensionType.alpn)
                        if not clntAlpnExt:
                            print 'client hello does not have application protocol extension'
                            print 'this should happen'
                            check_server_hello_result = False
                        if alpnExt.protocol_names[0] not in clntAlpnExt.protocol_names:
                            print 'application protocol name does not match'
                            print 'this should not happen'
                            check_server_hello_result = False
                    
                    if check_server_hello_result:
                        # we are about to do key generation
                        if self.state == MB_STATE_INITIAL_WAIT_SERVER_HELLO:
                            self.server_hello = server_hello
                        else:
                            self.retry_server_hello = server_hello
                        
                        if real_version > (3, 3):
                            # immitate TLS 1.3 client handshake
                            self.connection.version = real_version
                            self.state = MB_STATE_HANDSHAKE_DONE
                        else:
                            print 'real_version <= (3, 3)'
                            print 'this should not happen'
                    else:
                        self.state = MB_STATE_HANDSHAKE_ABORT
                elif self.state == MB_STATE_RETRY_WAIT_SERVER_HELLO:
                    # we received the second server hello
                    self.state = MB_STATE_HANDSHAKE_DONE
                else:
                    print 'we received server hello at unexpected state'
                    print 'this should not happen'
            elif hello_retry != None:
                # we received hello_retry
                if self.state == MB_STATE_INITIAL_WAIT_SERVER_HELLO:
                    # we received the first hello retry
                    self.state = MB_STATE_RETRY_WAIT_CLIENT_HELLO
                    client_hello_hash = self.connection._handshake_hash.copy()
                    prf_name, prf_size = self.connection._getPRFParams(hello_retry.cipher_suite)
                    self.connection._handshake_hash = HandshakeHashes()
                    writer = Writer()
                    writer.add(HandshakeType.message_hash, 1)
                    writer.addVarSeq(client_hello_hash.digest(prf_name), 1, 3)
                    self.connection._handshake_hash.update(writer.bytes)
                    self.connection._handshake_hash.update(hello_retry.write())
                    self.client_hello_retry_request = hello_retry
                elif self.state == MB_STATE_RETRY_WAIT_SERVER_HELLO:
                    self.state = MB_STATE_HANDSHAKE_ABORT
                    print 'we received multiple hello retries'
                    print 'this should happen in TLS 1.3'
                else:
                    print 'we received hello retry at unexpected state'
                    pritn 'this should happen'
            else:
                print 'client_hello, server_hello and hello_retry are all None'
                print 'this should not happen'
        elif content_type == ContentType.change_cipher_spec:
            pass
        elif content_type == ContentType.alert:
            pass
        else:
            # ContentType.application_data
            # we decrypt application data and perform DPI
    
# once we implemented our getMsg function, the following two functions won't be neededs
def mb_set_client_hello(record_data):
    """
    return constructed client hello from raw client hello wire data
    record_data: input, raw record data, of type bytearray
    """
    client_hello_data = record_data[6:]
    parser = Parser(client_hello_data)
    client_hello = ClientHello()
    client_hello.ssl2 = False
    client_hello.parse(parser)
    return client_hello

def mb_set_server_hello(record_data):
    """
    return constructed server hello from raw server hello wire data
    record_data: input, raw record data, of type bytearray
    """
    server_hello_data = record_data[6:]
    parser = Parser(server_hello_data)
    server_hello = ServerHello()
    server_hello.parse(parser)
    return server_hello

def mb_get_settings(client_hello, sever_hello):
    """
    return constructed handshake settings from client hello and server_hello
    client_hello: input, of type ClientHello
    server_hello: input, of type ServerHello
    """
    settings = HandshakeSettings()
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

# def mb_get_connection(client_hello):
#     """
#     return constructed TLSConnection from client hello
#     client_hello: input, of type ClientHello
#     """
#     settings = mb_get_settings(client_hello, None)
#     connection = TLSConnection(None)
#     connection._handshake_hash.update(client_hello.write())
#     return connection
    
def mb_get_server_hello(connection, settings, session, client_hello, server_hello):
    """
    server_hello: of type ServerHello
    """
    client_hello_hash = connection._handshake_hash.copy()
    connection._handshake_hash.update(server_hello.write())

if __name__ == '__main__':
    file = open('client_hello.raw', 'r')
    data = file.read()
    client_hello = mb_set_client_hello(bytearray(data))
    write_data = client_hello.write()
    if write_data == data[5:]:
        print 'mb_get_client_hello succeeded'
    else:
        print 'mb_get_client_hello failed'

    file.close()
    file = open('server_hello.raw', 'r')
    data = file.read()
    server_hello = mb_set_server_hello(bytearray(data))
    write_data = server_hello.write()
    if write_data == data[5:]:
        print 'mb_set_server_hello succeeded'
    else:
        print 'mb_set_server_hello failed'