import socket
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join


def create_cert():

    CERT_FILE = "my_cert.crt"
    KEY_FILE = "my_cert_keys.key"

            
    # creating a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

   # creating a certificate
    cert = crypto.X509()
    cert.get_subject().C = "GR"
    cert.get_subject().ST = "Chania"
    cert.get_subject().L = "Kounoupidiana"
    cert.get_subject().O = "HMMY"
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

# Establishing connection between the server and the client

s = socket.socket()
s.bind((host, port))

s.listen(1)
c, addr = s.accept()
print "Connection from: "+str(addr)


# Sending server certificate

send_cert = open("my_cert.crt").read()
print "sending certificate: " + str(send_cert)
c.send(send_cert)


# Establishing client-server communication

while True:
    data = c.recv(2048)
    if not data:
        break
    print "from connected user: " + str(data)
    data = str(data).upper()
    print "sending: " + str(data)
    c.send(data)

c.close()
