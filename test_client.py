from socket import *
from tlslite import TLSConnection
from tlslite.api import *

sock = socket.socket(AF_INET, SOCK_STREAM)
sock.connect(('127.0.0.1', 4443))
connection = TLSConnection(sock)
connection.handshakeClientCert()
request = "GET /bigger.pcap HTTP/1.0\r\n\r\n"
connection.send(request)
cnt = 0
while True:
    r = connection.recv(2048)
    if len(r) > 0:
        cnt = cnt + len(r)
        #print 'received ' + str(cnt)
        #print r
    else:
        print 'receive file completed'
        break