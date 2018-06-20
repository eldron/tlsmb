import socket
from tlslite import TLSConnection
from tlslite.api import *

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 4443))
connection = TLSConnection(sock)
connection.handshakeClientCert()
session = connection.session

# 2 \r\n
connection.send("GET / HTTP/1.0\r\n\r\n")

r = connection.recv(10240)
if r in (0, 1):
    print 'received 0 or 1'
elif isinstance(r, str):
    print 'received from server:'
    print r
else:
    print 'fuck'

connection.close()

session.resumable = True
print("Received {0} ticket[s]".format(len(connection.tickets)))
assert connection.tickets is session.tickets
print 'trying resumption handshake'
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 4443))
connection = TLSConnection(sock)
connection.handshakeClientCert(session = session)
# 2 \r\n
connection.send("GET / HTTP/1.0\r\n\r\n")

r = connection.recv(10240)
if r in (0, 1):
    print 'received 0 or 1'
elif isinstance(r, str):
    print 'received from server:'
    print r
else:
    print 'fuck'
connection.close()
# while True:
#     try:
#         r = connection.recv(10240)
#         if not r:
#             break
#         elif r in (0, 1):
#             print 'receivd 0 or 1'
#             pass
#         elif isinstance(r, str) or isinstance(r, bytearray):
#             print 'received form server:'
#             print r
#         else:
#             print 'fuck'
#     except socket.timeout:
#         print 'socket.timeout raised'
#         break
#     except TLSAbruptCloseError:
#         print 'TLSAbruptCloseError raised'
#         break
# connection.close()