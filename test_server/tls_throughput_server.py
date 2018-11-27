import socket
import sys
from tlslite.api import *

if __name__ == '__main__':
	if len(sys.argv) != 4:
		print 'usage: ' + sys.argv[0] + ' ip port filename'
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
		filename = sys.argv[3]
		file = open(filename, 'r')
		data = bytearray(file.read())
		filesize = len(data)
		file.close()

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind((ip, port))
		sock.listen(5)
		print 'server socket listening on ' + ip + ':' + str(port)
		client_sock, client_addr = sock.accept()
		conn = TLSConnection(client_sock)
		print 'about to handshake'
		conn.handshakeServer(certChain=cert_chain, privateKey=privateKey, reqCert=False)
		print 'handshakeServer succeeded'

		r = conn.recv(1024)
		block_size = 16384
		count = 0
		while count < filesize:
			if count + block_size < filesize:
				end = filesize
			else:
				end = count + block_size
			sent = conn.send(data[count:end])
			count += sent
		r = conn.recv(1024)
		print r
		conn.close()