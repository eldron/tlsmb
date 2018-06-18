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
            self.client_sock.write(header.write() + data)
        else:
            self.server_sock.write(header.write() + data)

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
            data = record_layer._decryptAndUnseal(header, data)
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
                # we do not yield change cipher spec
                # send change cipher spec to the other party
                if from_server:
                    self.client_sock.write(header.write() + parser.bytes)
                else:
                    self.server_sock.write(header.write() + parser.bytes)
            # If it's an SSLv2 ClientHello, we can return it as well, since
            # it's the only ssl2 type we support
            elif header.ssl2:
                yield (header, parser)
            else:
                # other types need to be put into buffers
                connection._defragmenter.add_data(header.type, parser.bytes)


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

        for result in self._getMsg(from_server = False, ContentType.handshake, HandshakeType.client_hello):
            if result in (0,1): yield result
            else: break
        client_hello = result

        # copy for calculating PSK binders
        self.client_connection._pre_client_hello_handshake_hash = self.client_connection._handshake_hash.copy()

        # update hashes
        self.client_connection._handshake_hash.update(client_hello.write())
        self.server_connection._handshake_hash.update(client_hello.write())

        if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO:
            self.client_hello = client_hello
        else:
            self.retry_client_hello = client_hello
                
        self.settings = mb_get_settings(self.client_hello)
        self.session = mb_get_resumable_session(self.client_hello)
        # we need to set session for client_connection and server_connection
        self.client_connection.session = self.session
        self.server_connection.session = self.session

        # change state
        if self.state == MB_STATE_INITIAL_WAIT_CLIENT_HELLO:
            self.state = MB_STATE_INITIAL_WAIT_SERVER_HELLO
        else:
            self.state = MB_STATE_RETRY_WAIT_SERVER_HELLO
        

    def mb_handle_hello_retry(self, hello_retry):
        # we received client hello retry request
        # for client_connection, we update hashes, then update hash with hello retry
        # for server_connection, we update hashes, then update hash with hello retry
        if self.state == MB_STATE_RETRY_WAIT_SERVER_HELLO:
            print 'we received client hello retry request at state MB_STATE_RETRY_WAIT_SERVER_HELLO'
            print 'this sould not happen'
        else:
            # we received the first hello retry
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
            self.server_connection._handshake_hash.update(hello_retry.write())

            # we may should update hashes for client_connection
            # find how server handles HRR
            prf_name, prf_size = self.client_connection._getPRFParams(cipherSuite)

            client_hello_hash = self.client_connection._handshake_hash.digest(prf_name)
            self.client_connection._handshake_hash = HandshakeHashes()
            writer = Writer()
            writer.add(HandshakeType.message_hash, 1)
            writer.addVarSeq(client_hello_hash, 1, 3)
            self.client_connection._handshake_hash.update(writer.bytes)
            self.client_connection._handshake_hash.update(hello_retry.write())

            self.client_hello_retry_request = hello_retry

            # we receive client hello and server hello again
            self.get_client_hello()
            self.get_server_hello()

    def check_server_hello(self, server_hello, real_version):
        # check server hello
        if self.client_hello_retry_request and self.client_hello_retry_request.cipher_suite != server_hello.cipher_suite:
            print 'hello_retry.cipher_suit != server_hello.cipher_suit'
            print 'this should not happen'
            return False
                    
        if real_version < self.settings.minVersion:
            print 'real_version < settings.minVersion'
            print 'this should not happen'
            return False

        if real_version > self.settings.maxVersion:
            print 'real_version > settings.maxVersion'
            print 'this should not happen'
            return False

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
        
        for result in self._getMsg(from_server = True, ContentType.handshake, HandshakeType.server_hello):
            if result in (0,1): yield result
            else: break
        unknown_record = result

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
            if server_hello.server_version >= (3, 3):
                ext = server_hello.getExtension(ExtensionType.supported_versions)
                if ext:
                    real_version = ext.version
            self.server_connection.version = real_version
            self.client_connection.version = real_version
            # check server hello
            if self.check_server_hello(server_hello, real_version):
                if self.state == MB_STATE_INITIAL_WAIT_SERVER_HELLO:
                    self.server_hello = server_hello
                else:
                    self.retry_server_hello = server_hello

                # we are about to do key generation
                self.mb_cal_ec_priv_key_from_server_hello(server_hello)
            else:
                print 'check server hello failed'
        else:
            self.mb_handle_hello_retry(hello_retry)
        
    

    # we need to implement our own getMsg function
    # this function can be called to:
    #   get client hello from client_connection
    #   get server_hello from server_connection
    #   get encrypted extensions from server_connection
    #   get certificate from server_connection
    #   get certificate verify from server_connection
    #   get finished from server_connection and client_connection
    # handshake hashes for connection are not automatically updated
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
                if self.version > (3, 3) and \
                        ContentType.handshake in expectedType and \
                        recordHeader.type == ContentType.change_cipher_spec:
                    # in fact we should not receive CCS here
                    print '_getMsg: received CCS, this should not happen'
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
                        print 'getMsg: received alert'
                        # alert = Alert().parse(p)

                        # #We either received a fatal error, a warning, or a
                        # #close_notify.  In any case, we're going to close the
                        # #connection.  In the latter two cases we respond with
                        # #a close_notify, but ignore any socket errors, since
                        # #the other side might have already closed the socket.
                        # if alert.level == AlertLevel.warning or \
                        #    alert.description == AlertDescription.close_notify:

                        #     #If the sendMsg() call fails because the socket has
                        #     #already been closed, we will be forgiving and not
                        #     #report the error nor invalidate the "resumability"
                        #     #of the session.
                        #     try:
                        #         alertMsg = Alert()
                        #         alertMsg.create(AlertDescription.close_notify,
                        #                         AlertLevel.warning)
                        #         for result in self._sendMsg(alertMsg):
                        #             yield result
                        #     except socket.error:
                        #         pass

                        #     if alert.description == \
                        #            AlertDescription.close_notify:
                        #         self._shutdown(True)
                        #     elif alert.level == AlertLevel.warning:
                        #         self._shutdown(False)

                        # else: #Fatal alert:
                        #     self._shutdown(False)

                        # #Raise the alert as an exception
                        # raise TLSRemoteAlert(alert)

                    #If we received a renegotiation attempt...
                    if recordHeader.type == ContentType.handshake:
                        print 'renegotiation attempt'
                        # subType = p.get(1)
                        # reneg = False
                        # if self._client:
                        #     if subType == HandshakeType.hello_request:
                        #         reneg = True
                        # else:
                        #     if subType == HandshakeType.client_hello:
                        #         reneg = True
                        # # Send no_renegotiation if we're not negotiating
                        # # a connection now, then try again
                        # if reneg and self.session:
                        #     alertMsg = Alert()
                        #     alertMsg.create(AlertDescription.no_renegotiation,
                        #                     AlertLevel.warning)
                        #     for result in self._sendMsg(alertMsg):
                        #         yield result
                        #     continue

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

                break

            # we've got a non-empty record of a type we expect. 

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
            print 'an exception was raised by a Parser or Message instance'
            yield 0
            # for result in self._sendError(AlertDescription.decode_error,
            #                              formatExceptionTrace(e)):
            #     yield result
    
    def server_connection_handle_server_hello(self, serverHello):
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

        prfName, prf_size = self.server_connection._getPRFParams(serverHello.cipher_suite)

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

        sr_handshake_traffic_secret = derive_secret(secret,
                                                    bytearray(b's hs traffic'),
                                                    self.server_connection._handshake_hash,
                                                    prfName)
        cl_handshake_traffic_secret = derive_secret(secret,
                                                    bytearray(b'c hs traffic'),
                                                    self.server_connection._handshake_hash,
                                                    prfName)

        # prepare for reading encrypted messages
        self.server_connection._recordLayer.calcTLS1_3PendingState(
            serverHello.cipher_suite,
            cl_handshake_traffic_secret,
            sr_handshake_traffic_secret,
            settings.cipherImplementations)

        self.server_connection._changeReadState()
        return (secret, cl_handshake_traffic_secret, sr_handshake_traffic_secret, prfName)

    # we received decrypted ecnrypted extensions from server_connection
    # update hashes
    # encrypted_extensions is of type EncryptedExtensions
    def server_connection_handle_encrypted_extensions(self, encrypted_extensions):
        self.server_connection._handshake_hash.update(encrypted_extensions.write())

    # we received decrypted certificate from server_connection
    def server_connection_handle_certificate(self, certificate):
        self.server_connection._handshake_hash.update(certificate.write())

    # we received decrypted certificate verify from server_connection
    def server_connection_handle_certificate_verify(self, certificate_verify):
        self.server_connection._handshake_hash.update(certificate_verify.write())

    # we received decrypted finished from server_connection
    def server_connection_handle_server_finished(self, finished):
        self.server_connection._handshake_hash.update(finished.write())
        server_finish_hs = self._handshake_hash.copy()
        self.server_connection._changeWriteState()
        return server_finish_hs

    # we received decrypted finished from client_connection
    def server_connection_handle_client_finished(self, finished, secret, prf_size, prfName, server_finish_hs, certificate):
        self.server_connection._handshake_hash.update(finished.write())
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

    # needs to figure out settings, session and session cache
    
    def client_connection_handle_server_hello(self, server_hello):
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
            connection._handshake_hash.update(server_hello.write())
            # calculate ECDH key
            prf_name, prf_size = connection._getPRFParams(cipherSuite)
            secret = bytearray(prf_size)
            share = clientHello.getExtension(ExtensionType.key_share)
            share_ids = [i.group for i in share.client_shares]
            # we read selected group from server hello
            selected_group = server_hello.getExtension(ExtensionType.key_share).server_share
            cl_key_share = next(i for i in share.client_shares if i.group == selected_group)
            
            # we read psk from server hello
            # if server agreed to perform resumption, find the matching secret key
            serverHello = server_hello
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
                        ident, self.session.resumptionMasterSecret,
                        self.session.tickets)
            else:
                psk = bytearray(prf_size)

            psks = clientHello.getExtension(ExtensionType.pre_shared_key)
            psk_types = clientHello.getExtension(ExtensionType.psk_key_exchange_modes)
            

            if psk is None:
                psk = bytearray(prf_size)

            kex = connection._getKEX(selected_group, version)
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

            return (secret, prf_name)

    # we received decrypted encrypted extensions from server_connection
    # update hashes for client_connection
    # encrypted_extensions is of type EncryptedExtensions
    def client_connection_handle_encrypted_extensions(self, encrypted_extensions):
        self.client_connection._handshake_hash.update(encrypted_extensions.write())

    # we received decrypted certificate from server_connection
    # update hashes for client_connection
    # certificate is of type Certificate
    def client_connection_handle_certificate(self, certificate, secret, prf_name):
        self.client_connection._handshake_hash.update(certificate.write())
        return (secret, prf_name)
    
    # we received decrypted certificate verify from server_connection
    # update hashes for client connection
    # certificate_verify is of type CertificateVerify
    def client_connection_handle_certificate_verify(self, certificate_verify, secret, prf_name):
        self.client_connection._handshake_hash.digest(prf_name)
        # maybe we do not need the above
        self.client_connection._handshake_hash.update(certificate_verify.write())
        return (secret, prf_name)

    # we received decrypted finished from server_connection
    # finished is of type Finished
    def client_connection_handle_server_finished(self, finished, secret, prf_name):
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
        return (secret, exporter_master_secret, prf_name)

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

    def client_connection_handle_tickets(self, tickets):

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
        
        if srKex.group == GroupName.x25519:
            self.curve_name = 'x25519'
            # read previous ec public key
            # bytearray of length 32
            self.prev_pubkey_filename = self.curve_name + '.pubkey'
            pubkey_file = open(self.prev_pubkey_filename, 'r')
            self.prev_public_key = pubkey_file.read()
            self.alpha = bytearray(32)
            self.alpha[31] = 2
        elif srKex.group == GroupName.secp256r1:
            self.curve_name = 'secp256r1'
            self.prev_pubkey_filename = self.curve_name + '.pubkey'
            pubkey_file = open(self.prev_pubkey_filename, 'r')
            curve = getCurveByName(self.curve_name)
            self.prev_public_key = decodeX962Point(pubkey_file.read(), curve)
            self.alpha = long(2)
        elif srKex.group == GroupName.secp384r1:
            self.curve_name = 'secp384r1'
            self.prev_pubkey_filename = self.curve_name + '.pubkey'
            pubkey_file = open(self.prev_pubkey_filename, 'r')
            curve = getCurveByName(self.curve_name)
            self.prev_public_key = decodeX962Point(pubkey_file.read(), curve)
            self.alpha = long(2)
        elif srKex.group == GroupName.secp521r1:
            self.curve_name = 'secp521r1'
            self.prev_pubkey_filename = self.curve_name + '.pubkey'
            pubkey_file = open(self.prev_pubkey_filename, 'r')
            curve = getCurveByName(self.curve_name)
            self.prev_public_key = decodeX962Point(pubkey_file.read(), curve)
            self.alpha = long(2)
        else:
            print 'server selected unsupported group'
            print 'this should not happen'
    
        # now calculate ec private key
        self.mb_ec_private_key = gen_private_key_for_middlebox(self.curve_name, self.alpha, self.prev_public_key)

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

    def middleman(self):
        """
        after the socks5 proxy is set, this function is called
        """
        self.state = MB_STATE_INITIAL_WAIT_CLIENT_HELLO
        # we receive client hello from self.client_connection
        self.get_client_hello()
        self.get_server_hello() # handles client hello retry request
        # now ec private key is calculated
        if self.retry_server_hello:
            server_hello = self.retry_server_hello
        else:
            server_hello = self.server_hello
        server_secret, server_cl_handshake_traffic_secret, server_sr_handshake_traffic_secret, server_prfName = self.server_connection_handle_server_hello(server_hello)
        client_secret, client_prf_name = self.client_connection_handle_server_hello(server_hello)
        
        # now read encrypted extensions
        for result in self._getMsg(from_server = True, ContentType.handshake, HandshakeType.encrypted_extensions):
            if result in (0,1): yield result
            else: break
        self.encrypted_extensions = result
        self.server_connection_handle_encrypted_extensions(self.encrypted_extensions)
        self.client_connection_handle_encrypted_extensions(self.encrypted_extensions)

        # now read certificate and certificate verify from server_connection

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