import sys, argparse, requests, base64, struct, json, pem
from cryptography.hazmat.backends import default_backend, interfaces
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, keywrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#Init command line parser
def createParser():	
	parser = argparse.ArgumentParser()
	subparsers = parser.add_subparsers(dest='command')

	generate_RSAkey_parser = subparsers.add_parser('generate-key-pair')
	request_SPK_parser = subparsers.add_parser('request-SPK')
	request_price_parser = subparsers.add_parser('request-price-list')
	print_all_keys_parser = subparsers.add_parser('print-all-keys')
	send_order_parser = subparsers.add_parser('send-order')

	return parser

#Read all private keys from key store
def readPrivateKeys():
	pem_encr_postfix = '-----END ENCRYPTED PRIVATE KEY-----\n'
	keys = []
	key = '';

	try:
		#read from file
		with open('keyStore.pem', 'r') as file:
			serKey = file.readlines()

		for i in serKey:
			key += i;

			if(i == pem_encr_postfix):
				enc_pem = serialization.load_pem_private_key(bytes(key, 'utf-8'), password=b'hellothere', backend=default_backend())
				keys.append(enc_pem)
				key = ''
	except FileNotFoundError:
		print("No keys. Generate it by use 'generateKeyPair'")
	return keys

#Create RSA private key
def generateKeyPair():
	#create privateKey
	privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

	#serialize it
	pem_key = privateKey.private_bytes(
 		encoding=serialization.Encoding.PEM,
 		format=serialization.PrivateFormat.PKCS8,
 		encryption_algorithm=serialization.BestAvailableEncryption(b'hellothere')
 		)

	#write in pem file
	with open('keyStore.pem', 'ab') as file:
		file.write(pem_key)
	print("Keys're generated")

#Print keys
def printAllKeys():
	keys = _readPrivateKeys();
	if(keys != []):	
		for i in keys:
			print(i)

#Request data from server
def request_data(url, public_key):
	public_key_bytes = public_key.public_bytes(
		encoding=serialization.Encoding.DER,
		format=serialization.PublicFormat.SubjectPublicKeyInfo)

	b64_public_key = (base64.b64encode(public_key_bytes)).decode('utf8')

	header = {'key' : json.dumps(b64_public_key)}

	response = requests.get(url, headers=header)

	return base64.b64decode(response.content)

#Restore the data if it was encrypted with AES
def restore_data(encr_server_response, private_key):
	encr_aes = []
	encr_iv = []
	encr_data = []

	index = 0
	while(index < 256):
		encr_aes.append(encr_server_response[index])
		index += 1
	
	while(index < 512):
		encr_iv.append(encr_server_response[index])
		index += 1

	while(index < len(encr_server_response)):
		encr_data.append(encr_server_response[index])
		index += 1

	aes_bytes = private_key.decrypt(
		encr_aes,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	iv_bytes = private_key.decrypt(
		encr_iv,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	cipher = Cipher(algorithms.AES(aes_bytes), modes.CBC(iv_bytes), backend=default_backend())
	decr = cipher.decryptor()
	data = decr.update(encr_data) + decr.finalize()

	decr_data = []
	data_index = len(data) - 1;

	while(data_index > 0):
		if(data[data_index] == 14):
			data_index -= 1
			continue
		else:
			break
	index = 0;

	while(index < data_index + 1):
		decr_data.append(data[index])
		index += 1

	return decr_data	

#SPK - server public key
def requestSPK():
	key = readPrivateKeys()

	if(key != []):
		private_key = key[len(key) - 1]
		encr_server_public_key = request_data('http://localhost:8080/getServerPublicKey', private_key.public_key())

		server_public_key_bytes = restore_data(encr_server_public_key, private_key)

		return serialization.load_der_public_key(bytes(server_public_key_bytes), backend=default_backend())
	else:
		print("No keys. Generate it by use 'generate-key-pair'")

#Request price lsit
def requestPriceList():
	key = readPrivateKeys()

	if(key != []):
		private_key = key[len(key) - 1]
		encr_price_list = request_data('http://localhost:8080/getProducts', private_key.public_key())

		return bytes(restore_data(encr_price_list, private_key))
	else:
		print("No keys. Generate it by use 'generate-key-pair'")

#Main menthod(used to parse command)
if __name__ == '__main__':
    parser = createParser()
    namespace = parser.parse_args()

    if namespace.command == 'generate-key-pair':
        generateKeyPair()

    elif namespace.command == 'print-all-keys':
    	printAllKeys();

    elif namespace.command == 'request-SPK':
        response = requestSPK()
        print(response)

    elif namespace.command == 'request-price-list':
    	response = requestPriceList()
    	print(response)

    # elif namespace.command == 'send-order':
