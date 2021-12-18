import tools
import socket
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join


def create_cert():

	CERT_FILE = "client2_cert.crt"
	KEY_FILE = "client2_key.key"

			
	# creating a key pair
	k = crypto.PKey()
	k.generate_key(crypto.TYPE_RSA, 2048)

	# creating a certificate
	cert = crypto.X509()
	cert.get_subject().C = "GR"
	cert.get_subject().ST = "Chania"
	cert.get_subject().L = "Kounoupidiana"
	cert.get_subject().O = "Central Committee"
	cert.get_subject().OU = "Technical University of Crete"
	cert.get_subject().CN = gethostname()
	cert.set_serial_number(1000)
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(10*365*24*60*60)   #10 years
	cert.set_issuer(cert.get_subject())
	cert.set_pubkey(k)
	cert.sign(k, 'sha256')

	print cert.get_issuer().get_components()

	open(CERT_FILE, "wt").write(
		crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
	open(KEY_FILE, "wt").write(
		crypto.dump_privatekey(crypto.FILETYPE_PEM, k))



create_cert()


host = '127.0.0.1'
port = 5000


# Generating a RSA key pair

rsa_key_l = 2048
key_pair_client = tools.key_generation(rsa_key_l)

e = key_pair_client[0][0]
n = key_pair_client[1][1]
d = key_pair_client[1][0]


# Writing client RSA keys to a file

rsa_file_name_client = "client2_rsa_keys.pair"
tools.file_write_line(rsa_file_name_client, str(e)+'\n'+str(n)+'\n'+str(d))


# Establishing connection between the server and the client

s = socket.socket()
s.connect((host, port))


# Sending client certificate

send_cert2 = open("client2_cert.crt").read()
print "Sending client certificate. Contents: " + str(send_cert2)
s.send(send_cert2)


# Receiving server certificate

cert_recv = s.recv(2048)
print 'Received server certificate. Contents: ' + str(cert_recv)
open("server2_cert.crt", "w").write(cert_recv)


# Verifying server certificate

print "Certificate authentication (client)"

if(tools.verify_certificate(cert_recv)==True):
	print "Success! Server certificate is verified!"
else:
	print "Certificate authentication failed"


# After receiving the symmetric key as a string from the server, it is converted to byte array so it can be decrypted with RSA

rsa_symmetric_key = s.recv(10*2048)
rsa_symmetric_key2 = tools.string_to_byte_array(rsa_symmetric_key)

rsa_dec_symmetric_key = tools.rsa_decrypt(rsa_symmetric_key2, d, n)
print 'The symmetric key (after decryption) received by the client is: ' + str(rsa_dec_symmetric_key)


# Establishing 2-way encrypted communication

message = raw_input("\nServer and Client may now start communicating with encrypted messages...\n\n-> ")
while message != 'end':

	message = tools.aes_padding(message)
	message = tools.CBC_encrypt(message, rsa_dec_symmetric_key, tools.get_IV())
	print "Encrypted message sent by the client to the server: " + str(message)
	s.send(message)

	data_rec = s.recv(2048)
	print "Message the client received from the server: " + str(data_rec)

	data = tools.CBC_decrypt(data_rec, rsa_dec_symmetric_key, tools.get_IV())
	data = tools.aes_reverse_padding(data)
	print "Decrypted message: " + str(data)
	
	message = raw_input("\n-> ")

s.close()