import socket
import sys

if __name__ == '__main__':
    client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_address = 'inspection_server'
    client_sock.connect(server_address)
    # read file, send data to server for inspection, read results
    fin = open('bigger.pcap', 'r')
    data = fin.read()

# if __name__ == '__main__':
#     sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
#     server_address = 'mysocket'
#     sock.connect(server_address)
#     # receive data from server
#     data = sock.recv(1000)
#     # send data to server
#     sock.sendall('this is the first msg from client\n')
#     sock.sendall('this is the second msg from client\n')
#     sock.sendall('this is the third msg from client\n')

#     sock.close()