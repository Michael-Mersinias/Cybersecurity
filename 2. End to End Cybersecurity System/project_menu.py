# Name: Mersinias Michail
# AM: 2013030057

import tools

def main_func():

	option = 10
	mode = 'a'
	rsa_enc = [1467475930L, 573131644L, 139212273L]
	flag_option = 0

	while(option!=0):

		print 'Press 1 to select AES Encryption'
		print 'Press 2 to select AES Decryption'
		print 'Press 3 to select SHA2 Hashing'
		print 'Press 4 to select Signature Signing'
		print 'Press 5 to select Signature Verification'
		print 'Press 6 to select Certificate Verification'
		print 'Press 0 to Exit'

		option = input("Make your choice: ")

		if(option==1):
			
			print "AES encrypt"
			print "Suggested: aes_plaintext_file.txt"
			aes_plaintext_file_name = raw_input("Please enter the name of the file containing the plaintext: ")
			aes_data = tools.file_read(aes_plaintext_file_name)
			aes_data = tools.aes_padding(aes_data)
			print 'Original message: ',aes_data
			aes_key = tools.pick_key()

			i_v = '0102030405060708090a0b0c0d0e0f10'

			#i_v = raw_input("Please enter the initialization vector: ")
			#while(len(str(i_v))<32):
			#	print 'Recommended: 0102030405060708090a0b0c0d0e0f10'
			#	i_v = raw_input("Please enter a correctly sized initialization vector: ")

			cbc_enc = tools.CBC_encrypt(aes_data, aes_key, i_v)
			print 'Encrypted message: ',cbc_enc

			aes_enc_file_name = "aes_enc_file.txt"
			tools.file_write(aes_enc_file_name, cbc_enc)

			if(input("Press 0 to exit or any other key to continue: ")==0):
				option = 0

		elif(option==2):

			print "AES decrypt"
			choice1 = input('Press 1 if you wish to decrypt the message you just encrypted: ')
			print "Suggested: aes_enc_file.txt"
			aes_encrypted_file_name = raw_input("Please enter the name of the file containing the encrypted text: ")

			if(choice1==1):
				aes_key = aes_key
				aes_data = tools.file_read(aes_encrypted_file_name)
				i_v = i_v
			else:
				aes_data = tools.file_read(aes_encrypted_file_name)
				aes_key = raw_input("Please enter the same symmetric key you used for encryption: ")
				i_v = '0102030405060708090a0b0c0d0e0f10'

				#i_v = raw_input("Please enter the initialization vector: ")
				#while(len(str(i_v))<32):
				#	print 'Recommended: 0102030405060708090a0b0c0d0e0f10'
				#	i_v = raw_input("Please enter a correctly sized initialization vector: ")

			cbc_dec = tools.CBC_decrypt(aes_data, aes_key, i_v)
			cbc_dec = tools.aes_reverse_padding(cbc_dec)
			print 'Decrypted message: ',cbc_dec

			aes_dec_file_name = "aes_dec_file.txt"
			tools.file_write(aes_dec_file_name, cbc_dec)

			if(input("Press 0 to exit or any other key to continue: ")==0):
				option = 0

		elif(option==3):

			print "sha256 hash"
			print "Suggested: sha256_file.txt"
			sha_file_name = raw_input("Please enter the name of the file containing the plaintext to be hashed: ")
			msg_4 = tools.file_read(sha_file_name)
			
			hashed_msg = tools.SHA256(msg_4)
			print 'Hashed message: ',hashed_msg

			hashed_file_name = "hashed_file.txt"
			tools.file_write(hashed_file_name, hashed_msg)

			if(input("Press 0 to exit or any other key to continue: ")==0):
				option = 0

		elif(option==4):

			print "RSA based Signature"

			rsa_key_len = 1024
			rsa_key_pair = tools.key_generation(rsa_key_len)

			sign_e = rsa_key_pair[0][0]
			sign_n = rsa_key_pair[1][1]
			sign_d = rsa_key_pair[1][0]


			print "Suggested: sign_file.txt"
			sign_file_name = raw_input("Please enter the name of the file to be signed: ")
			print "Suggested: private_key.sec"
			private_key_file_name = raw_input("Please enter the name of the file containing the RSA private key: ")
			tools.file_write_line(private_key_file_name, str(sign_d)+'\n'+str(sign_n))

			m = tools.file_read(sign_file_name)

			file_tempy_1 = open(private_key_file_name, "r")
			d = file_tempy_1.readline()
			n = file_tempy_1.readline()
			file_tempy_1.close()

			digital_signature = tools.sign(m, int(d), int(n))
			print 'Signed: ',digital_signature

			signed_file_name = "signed_file.txt"
			tools.file_write(signed_file_name, str(digital_signature))

			if(input("Press 0 to exit or any other key to continue: ")==0):
				option = 0

		elif(option==5):

			print "Signature verification"
			choice5 = input('Press 1 if you wish to verify the signature you just signed: ')
			print "Suggested: public_key.pub"
			public_key_file_name = raw_input("Please enter the name of the file containing the RSA public key: ")
			tools.file_write_line(public_key_file_name, str(sign_e)+'\n'+str(sign_n))

			if(choice5==1):
				m = m
				c = digital_signature
				e = tools.file_read_line(public_key_file_name)
				n = n
			else:
				print "Suggested: sign_file.txt"
				sign_file_name = raw_input("Please enter the name of the file to be signed: ")
				print "Suggested: signed_file.txt"
				signature_file_name = raw_input("Please enter the name of the file containing the digital signature: ")
				m = tools.file_read(sign_file_name)
				c = tools.file_read(signature_file_name)

				file_tempy_2 = open(public_key_file_name, "r")
				e = file_tempy_2.readline()
				n = file_tempy_2.readline()
				file_tempy_2.close()

			print 'Verified: ',tools.verify(m, int(c), int(e), int(n))

			if(input("Press 0 to exit or any other key to continue: ")==0):
				option = 0

		elif(option==6):
			print "Certificate verification"
			certy_name = raw_input("Please enter the name of the certificate you want to verify: ")

			certy_contents = open(certy_name, "r").read()

			tools.verify_certificate(certy_contents)


			if(input("Press 0 to exit or any other key to continue: ")==0):
				option = 0

main_func()