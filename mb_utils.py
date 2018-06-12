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
        self.connection = None
        self.session = None

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

    def mb_hanlde_encrypted_extensions(self):

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