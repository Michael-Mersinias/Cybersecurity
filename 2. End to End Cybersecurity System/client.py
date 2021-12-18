import socket
import tools
from OpenSSL import crypto, SSL

host = '127.0.0.1'
port = 5000


# Establishing connection between the server and the client

s = socket.socket()
s.connect((host, port))


# Receiving server certificate

cert_recv = s.recv(2048)
print 'Received: ' + str(cert_recv)
open("my_cert2.crt", "w").write(cert_recv)


# Verifying server certificate

print "Certificate verification"

if(tools.verify_certificate(cert_recv)==True):
	print "Success!"
else:
	print "No way!"


# Establishing client-server communication

message = raw_input("-> ")
while message != 'end':
    s.send(message)
    data = s.recv(2048)
    print 'Received from server: ' + str(data)
    message = raw_input("-> ")

s.close()