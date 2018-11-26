import socket
import sys
from tlslite.api import *

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print 'usage: ' + sys.argv[0] + 'ip port'
	else:
		private_key_file = "serverX509Key.pem"
		cert_file = "serverX509Cert.pem"
		s = open(private_key_file, "rb").read()
		if sys.version_info[0] >= 3:
			s = str(s, 'utf-8')
		# OpenSSL/m2crypto does not support RSASSA-PSS certificates
		privateKey = parsePEMKey(s, private=True, implementations=["python"])

		s = open(cert_file, "rb").read()
		if sys.version_info[0] >= 3:
			s = str(s, 'utf-8')
		x509 = X509()
		x509.parse(s)
		cert_chain = X509CertChain([x509])

		ip = sys.argv[1]
		port = int(sys.argv[2])
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind((ip, port))
		sock.listen(5)
		print 'server socket listening on ' + ip + ':' + str(port)
		client_sock, client_addr = sock.accept()
		conn = TLSConnection(client_sock)
		print 'about to handshake'
		conn.handshakeServer(certChain=cert_chain, privateKey=privateKey, reqCert=False)
		print 'handshakeServer succeeded'

		while True:
			while True:
				request = conn.recv(2000)
				if isinstance(request, str):
					break
			conn.sendall("tls test delay response")