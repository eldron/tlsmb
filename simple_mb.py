# python 2

import sys
import SocketServer as socketserver
import threading
import socket
import ipaddress
#import selectors2 as selectors
import select
from mb_utils import *

udp_bind_port = 10000
udp_associate_support = False

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	pass

def print_auth_method(method):
	if method == 0x00:
		print 'no authentication required'
	elif method == 0x01:
		print 'gssapi'
	elif method == 0x02:
		print 'username password'
	elif 0x03 <= method and method <= 0x7f:
		print 'IANA assigned'
	elif 0x80 <= method and method <= 0xfe:
		print 'reserved for private methods'
	else:
		print 'no acceptable methods'

def parse_method_selection_msg(msg):
	version = ord(msg[0])
	number_of_methods = ord(msg[1])
	print 'version = ' + str(version)
	print 'number of authentication methods = ' + str(number_of_methods)

	i = 0
	while i < number_of_methods:
		print_auth_method(ord(msg[i + 2]))
		i = i + 1

# def recv_tls_tlsrecord(sock):
# 	# receive complete tls record from sock

def simple_forward_data(request, sock):
	request.setblocking(0)
	sock.setblocking(0)
	inputs = [request, sock]
	sock_data_len = 0
	while inputs:
		readable, writable, exceptional = select.select(inputs, [], inputs)
		for s in readable:
			data = s.recv(2048)
			if data:
				if s == request:
					sock.sendall(data)
				else:
					sock_data_len += len(data)
					#print 'sock_data_len = ' + str(sock_data_len)
					request.sendall(data)
					# if sock_data_len < 20000:
					# 	request.sendall(data)
			else:
				s.close()
				inputs.remove(s)
		for s in exceptional:
			s.close()
			inputs.remove(s)

# def simple_forward_data(request, sock):
# 	request.setblocking(False)
# 	sock.setblocking(False)
# 	request_list = []
# 	request_list_len = 0
# 	while True:
# 		data = request.recv(2048)
# 		sock.sendall(data)

# 		data = sock.recv(2048)
# 		if len(data) > 0:
# 			request_list.append(data)
# 			request_list_len += len(data)
# 			if request_list_len >= 16384:
# 				for item in request_list:
# 					request.sendall(item)
# 				request_list_len = 0

# request is connected to client
# sock is connected with server
def forward_data(request, sock, perform_inspection):
	if perform_inspection:
		inspection_client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		inspection_client_sock.connect('inspection_server')

	request.setblocking(False)
	sock.setblocking(False)
	sel = selectors.DefaultSelector()
	sel.register(request, selectors.EVENT_READ)
	sel.register(sock, selectors.EVENT_READ)
	server_data_count = 0
	client_data_count = 0
	request_list = []
	request_list_len = 0
	sock_list = []
	sock_list_len = 0
	while True:
		events = sel.select()
		for key, mask in events:
			if key.fileobj == sock:
				data = sock.recv(2048)
				request_list.append(data)
				request_list_len += len(data)
				if perform_inspection:
					data_len = len(data)
					if 0 < data_len and data_len <= 0xffff:
						server_data_count += data_len
						#print 'server_data_count = ' + str(server_data_count)
						high = (data_len & 0xff00) >> 8
						low = data_len & 0x00ff
						tosend = bytearray()
						tosend.append(high)
						tosend.append(low)
						tosend = tosend + data
						inspection_client_sock.sendall(tosend)
						reply = inspection_client_sock.recv(1)
				#request.sendall(data)
				print 'request_list_len = ' + str(request_list_len)
				if request_list_len >= 16384:
					for item in request_list:
						request.sendall(item)
					request_list = []
					request_list_len = 0
					print 'sent bulk data'
			else:
				data = request.recv(2048)
				# sock_list.append(data)
				# sock_list_len += len(data)
				# if perform_inspection:
				# 	data_len = len(data)
				# 	if 0 < data_len and data_len <= 0xffff:
				# 		high = (data_len & 0xff00) >> 8
				# 		low = data_len & 0x00ff
				# 		tosend = bytearray()
				# 		tosend.append(high)
				# 		tosend.append(low)
				# 		tosend = tosend + data
				# 		inspection_client_sock.sendall(tosend)
				# 		reply = inspection_client_sock.recv(1)
				sock.sendall(data)
				# print 'sock_list_len = ' + str(sock_list_len)
				# if sock_list_len >= 16384:
				# 	for item in sock_list:
				# 		sock.sendall(item)
				# 	sock_list = []
				# 	sock_list_len = 0
				# 	print 'sent bulk data'

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
	def handle(self):
		# receive version and authentication methods
		data = self.request.recv(1024)
		parse_method_selection_msg(data)
		# currently only support no authentication, send selected authentication method
		self.request.sendall(b'\x05\x00')

		# receive request details
		data = self.request.recv(1024)
		version_number = ord(data[0])
		cmd = ord(data[1])
		address_type = ord(data[3])
		requested_address = b''
		requested_port = 0

		if cmd == 0x01:
			if address_type == 0x01:
				# ipv4 address, the next 4 bytes are address
				#requested_address = data[4:8]
				requested_address = (ord(data[4]) << 24) | (ord(data[5]) << 16) | (ord(data[6]) << 8) | ord(data[7])
				# the next 2 bytes are port number in big endian
				#requested_port = int.from_bytes(data[8:10], byteorder = 'big')
				requested_port = (ord(data[8]) << 8) | ord(data[9])
			elif address_type == 0x03:
				# domain name, the first byte contains the domain name length
				address_len = data[4]
				requested_address = data[5: 5 + address_len]
				# the next 2 bytes are port number in big endian
				#requested_port = int.from_bytes(data[5 + address_len: 5 + address_len + 2], byteorder = 'big')
				value1 = ord(data[5 + address_len])
				value2 = ord(data[6 + address_len])
				requested_port = (value1 << 8) | value2
			elif address_type == 0x04:
				# ipv6 address, the next 16 bytes are address
				requested_address = data[4: 20]
				#requested_port = int.from_bytes(data[20:22], byteorder = 'big')
				requested_port = (ord(data[22]) << 8) | ord(data[21])
			else:
				print 'error: unexpected address type'

			# try to establish a connection with the requested address and port, and send reply to client
			# currently does not support ipv6
			if address_type == 0x01:
				requested_addr = ipaddress.ip_address(requested_address)
				print 'trying to connect to: ' + requested_addr.exploded
				connected = True
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.connect((requested_addr.exploded, requested_port))
				except socket.error as e:
					connected = False
					print 'socket error: ' + str(e)
				except socket.gaierror as e:
					connected = False
					print 'address related error: ' + str(e)

				if connected:
					# send succeeded reply
					succeeded_reply = b''
					succeeded_reply = succeeded_reply + b'\x05' # version number
					succeeded_reply = succeeded_reply + b'\x00' # succeeded
					succeeded_reply = succeeded_reply + b'\x00' # reserved
					succeeded_reply = succeeded_reply + b'\x01' # address type, ipv4 address
					bind_address, bind_port = sock.getsockname()
					succeeded_reply = succeeded_reply + ipaddress.ip_address(unicode(bind_address)).packed
					#succeeded_reply = succeeded_reply + bind_port.to_bytes(2, byteorder = 'big')
					succeeded_reply = succeeded_reply + chr((bind_port & 0x0000ff00) >> 8)
					succeeded_reply = succeeded_reply + chr(bind_port & 0x000000ff)
					self.request.sendall(succeeded_reply)
					self.request.setblocking(False)
					sock.setblocking(False)
					# forward and inspect data
					#forward_data(self.request, sock, False)
					simple_forward_data(self.request, sock)
				else:
					# send failed reply
					failed_reply = b''
					failed_reply = failed_reply + b'\x05' # version number
					failed_reply = failed_reply + b'\x01' # general SOCKS server failure
					failed_reply = failed_reply + b'\x00' # reserved
					failed_reply = failed_reply + b'\x01' + b'\x00' * 6
					self.request.sendall(failed_reply)
					self.request.close()
			elif address_type == 0x04:
				# ipv6 address, currently does not support, send failed reply
				failed_reply = b''
				failed_reply = failed_reply + b'\x05' # version number
				failed_reply = failed_reply + b'\x08' # address type not supported
				failed_reply = failed_reply + b'\x00' # reserved
				failed_reply = failed_reply + b'\x01' + b'\x00' * 6
				self.request.sendall(failed_reply)
				self.request.close()
			else:
				# domain name address
				print 'trying to connect to host:' + requested_address
				connected = True
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.connect((requested_address, requested_port))
				except socket.error as e:
					connected = False
					print 'socket error: ' + str(e)
				except socket.gaierror as e:
					connected = False
					print 'address related error: ' + str(e)

				if connected:
					# send succeed reply
					succeeded_reply = b''
					succeeded_reply = succeeded_reply + b'\x05' # version number
					succeeded_reply = succeeded_reply + b'\x00' # succeeded
					succeeded_reply = succeeded_reply + b'\x00' # reserved
					succeeded_reply = succeeded_reply + b'\x01' # address type, ipv4 address
					bind_address, bind_port = sock.getsockname()
					succeeded_reply = succeeded_reply + ipaddress.ip_address(unicode(bind_address)).packed
					#succeeded_reply = succeeded_reply + bind_port.to_bytes(2, byteorder = 'big')
					succeeded_reply = succeeded_reply + chr((bind_port & 0x0000ff00) >> 8)
					succeeded_reply = succeeded_reply + chr(bind_port & 0x000000ff)
					self.request.sendall(succeeded_reply)
					self.request.setblocking(False)
					sock.setblocking(False)
					# forward and inspect data
					#forward_data(self.request, sock, False)
					simple_forward_data(self.request, sock)
				else:
					# send failed reply
					failed_reply = b''
					failed_reply = failed_reply + b'\x05' # version number
					failed_reply = failed_reply + b'\x01' # general SOCKS server failure
					failed_reply = failed_reply + b'\x00' # reserved
					failed_reply = failed_reply + b'\x01' + b'\x00' * 6
					self.request.sendall(failed_reply)
					self.request.close()
		elif cmd == 0x02:
			# currently does not support bind, send failed reply to client
			# to support bind command, the proxy server needs to first create a server listening socket,
			# send the first reply to the client, then send the second reply when a connection is established

			failed_reply = b''
			failed_reply = failed_reply + b'\x05' # version number
			failed_reply = failed_reply + b'\x07' # command not supported
			failed_reply = failed_reply + b'\x00' # reserved
			failed_reply = failed_reply + b'\x01' + b'\x00' * 6
			self.request.sendall(failed_reply)
			self.request.close()
		else:
			# udp associate
			if udp_associate_support:
				if address_type == 0x04:
					# currently does not support ipv6, send failed reply
					failed_reply = b''
					failed_reply = failed_reply + b'\x05' # version number
					failed_reply = failed_reply + b'\x08' # address type not supported
					failed_reply = failed_reply + b'\x00' # reserved
					failed_reply = failed_reply + b'\x01' + b'\x00' * 6
					self.request.sendall(failed_reply)
					self.request.close()
				else:
					# create a udp socket for the client
					udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					udp_sock.bind(('localhost', udp_bind_port))
					udp_bind_port = udp_bind_port + 1

					succeeded_reply = b''
					succeeded_reply = succeeded_reply + b'\x05' # version number
					succeeded_reply = succeeded_reply + b'\x00' # succeeded
					succeeded_reply = succeeded_reply + b'\x00' # reserved
					succeeded_reply = succeeded_reply + b'\x01' # address type, ipv4 address
					bind_address, bind_port = udp_sock.getsockname()
					succeeded_reply = succeeded_reply + ipaddress.ip_address(unicode(bind_address)).packed
					#succeeded_reply = succeeded_reply +  bind_port.to_bytes(2, byteorder = 'big')
					succeeded_reply = succeeded_reply + chr((bind_port & 0x0000ff00) >> 8)
					succeeded_reply = succeeded_reply + chr(bind_port & 0x000000ff)
					self.request.sendall(succeeded_reply)
					# forward data
					data, client_addr = udp_sock.recvfrom(2048)
					# blablabla, to do
			else:
				failed_reply = b''
				failed_reply = failed_reply + b'\x05' # version number
				failed_reply = failed_reply + b'\x07' # command not supported
				failed_reply = failed_reply + b'\x00' # reserved
				failed_reply = failed_reply + b'\x01' + b'\x00' * 6
				self.request.sendall(failed_reply)
				self.request.close()

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print 'usage: ' + sys.argv[0] + ' port_number'
	else:
		port = int(sys.argv[1])
		server = ThreadedTCPServer(('localhost', port), ThreadedTCPRequestHandler)
		server.serve_forever()
		# server_thread = threading.Thread(target = server.serve_forever)
		# server_thread.daemon = True
		# server_thread.start()
		# while True:
		# 		pass
