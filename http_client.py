import socket
import sys
import ipaddress

# the naive version

def direct_download_file(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, server_port))
    sock.sendall("GET /bigger.pcap HTTP/1.0\r\n\r\n")
    count = 0
    file_size = 9637200
    block_size = 1024 * 1024
    while True:
        r = sock.recv(block_size)
        if len(r) > 0:
            count += len(r)
            if count >= file_size:
                print 'received ' + str(count) + 'bytes data, exiting'
                break
        else:
            print 'received ' + str(count) + ' bytes data, receive file completed'
            break

if __name__ == '__main__':
    if len(sys.argv) != 5 and len(sys.argv) != 3:
        print 'usage: ' + sys.argv[0] + ' proxy_ip proxy_port server_ip server_port'
        print 'usage: ' + sys.argv[0] + ' server_ip server_port'
    elif len(sys.argv) == 3:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
        direct_download_file(server_ip, server_port)
    else:
        file_size = 9637200
        proxy_ip = sys.argv[1]
        proxy_port = int(sys.argv[2])
        server_ip = sys.argv[3]
        server_port = int(sys.argv[4])
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
            # now use sock to download file from HTTP server
            sock.sendall("GET /bigger.pcap HTTP/1.0\r\n\r\n")
            count = 0
            block_size = 1024 * 1024
            while True:
                r = sock.recv(block_size)
                if len(r) > 0:
                    count += len(r)
                    #print 'received ' + str(count) + 'bytes data'
                    if count >= file_size:
                        print 'received ' + str(count) + 'bytes data, exiting'
                        break
                else:
                    print 'received ' + str(count) + ' bytes data, receive file completed'
                    break