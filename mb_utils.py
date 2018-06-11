from tlslite.handshakesettings import *
from tlslite.messages import *
from tlslite.extensions import *
from tlslite.utils.codec import *
from tlslite import TLSConnection
from tlslite.session import *

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

def mb_get_connection(client_hello):
    """
    return constructed TLSConnection from client hello
    client_hello: input, of type ClientHello
    """
    settings = mb_get_settings(client_hello, None)
    connection = TLSConnection(None)
    connection._handshake_hash.update(client_hello.write())
    return connection
    
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