from tlslite.handshakesettings import *
from tlslite.messages import *
from tlslite.extensions import *
from tlslite.utils.codec import *


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

def mb_get_settings(client_hello):
    """
    return constructed handshake settings from client hello
    client_hello: input, of type ClientHello
    """
    settings = HandshakeSettings()

    return settings
    
if __name__ == '__main__':
    file = open('client_hello.raw', 'r')
    data = file.read()
    client_hello = mb_set_client_hello(bytearray(data))
    write_data = client_hello.write()
    if write_data == data[5:]:
        print 'mb_get_client_hello succeeded'
    else:
        print 'mb_get_client_hello failed'