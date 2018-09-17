import socket
from tlslite import TLSConnection
from tlslite.api import *
import sys
import ipaddress
import mb_utils

# the naive version

if __name__ == '__main__':
    if len(sys.argv) != 7:
        print 'usage: ' + sys.argv[0] + ' proxy_ip proxy_port server_ip server_port cipher_suite curve_name'
        print 'cipher_suite can be aes128gcm, aes256gcm or chacha20-poly1305'
        print 'curve_name can be x25519, x448, secp256r1, secp384r1 or secp521r1'
    else:
        proxy_ip = sys.argv[1]
        proxy_port = int(sys.argv[2])
        server_ip = sys.argv[3]
        server_port = int(sys.argv[4])
        cipher_suite = sys.argv[5]
        curve_name = sys.argv[6]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((proxy_ip, proxy_port))
        # send version and authentication method to the socks 5 proxy 
        sock.sendall(b'\x05\x01\x00')
        # read version and authentication method from the socks 5 proxy
        tmp = sock.recv(2)
        if tmp != b'\x05\x00':
            print 'did not receive 0x0500 from socks 5 proxy'
            print 'this should not happen'
        else:
            print 'received version and authentication from socks 5 proxy'

        # send request to the socks 5 proxy
        # we use ip address 
        request = b'\x05\x01\x00\x01' + ipaddress.ip_address(unicode(server_ip)).packed
        request = request + chr((server_port & 0x0000ff00) >> 8)
        request = request + chr(server_port & 0x000000ff)
        sock.sendall(request)

        # receive reply from socke 5 proxy
        failed_reply = b''
        failed_reply = failed_reply + b'\x05' # version number
        failed_reply = failed_reply + b'\x01' # general SOCKS server failure
        failed_reply = failed_reply + b'\x00' # reserved
        failed_reply = failed_reply + b'\x01' + b'\x00' * 6

        reply = sock.recv(10)
        if len(reply) != 10:
            print 'reply length is not 10'
            print 'this should not happen'
        elif reply == failed_reply:
            print 'received failed reply'
        else:
            print 'received succeeded reply, socks 5 proxy established connection with the remote server'
            # now use sock to establish TLS 1.3 connection with the remote server
            connection = TLSConnection(sock)
            settings = HandshakeSettings()
            settings.cipherNames = [cipher_suit]
            settings.eccCurves = list([curve_name])
            settings.defaultCurve = curve_name
            settings.keyShares = [curve_name]
            mb_utils.fake_handshakeClientCert(connection, settings=settings)
            # 2 \r\n
            connection.send("GET /bigger.pcap HTTP/1.0\r\n\r\n")
            count = 0
            block_size = 20000
            while True:
                r = connection.recv(block_size)
                if r in (0, 1):
                    print 'received 0 or 1'
                elif isinstance(r, str):
                    if len(r) > 0:
                        print 'received ' + str(len(r)) + ' bytes'
                        count = count + len(r)
                    else:
                        print 'received ' + str(count) + 'bytes data, receive file completed'
                        break
                else:
                    print 'fuck'
            #connection.close()