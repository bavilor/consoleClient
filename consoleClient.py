import sys, argparse, requests, base64, struct, json, pem, os, struct
from cryptography.hazmat.backends import default_backend, interfaces
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes, keywrap, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#Init command line parser
def create_parser():	
	parser = argparse.ArgumentParser()
	subparsers = parser.add_subparsers(dest='command')

	generate_RSAkey_parser = subparsers.add_parser('generate-key-pair')
	request_SPK_parser = subparsers.add_parser('request-SPK')
	request_price_parser = subparsers.add_parser('request-price-list')
	print_all_keys_parser = subparsers.add_parser('print-all-keys')
	
	send_order_parser = subparsers.add_parser('send-order')
	send_order_parser.add_argument('--name', '-n', nargs='+')
	send_order_parser.add_argument('--amount', '-a', nargs='+')

	request_orders_list_parser = subparsers.add_parser('print-all-orders')

	return parser

#Read all private keys from key store
def read_private_keys():
	pem_encr_postfix = '-----END ENCRYPTED PRIVATE KEY-----\n'
	keys = []
	key = ''

	try:
		#read from file
		with open('keyStore.pem', 'r') as file:
			serKey = file.readlines()

		for i in serKey:
			key += i;

			if i == pem_encr_postfix:
				enc_pem = serialization.load_pem_private_key(bytes(key, 'utf-8'), password=b'hellothere', backend=default_backend())
				keys.append(enc_pem)
				key = ''
	except FileNotFoundError:
		print("No keys. Generate it by use 'generateKeyPair'")
	return keys

#Create RSA private key
def generate_key_pair():
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

#Decrypt data
def decrypt_data(private_key, aes_bytes, iv_bytes, encr_data):
	try:
		aes_bytes = private_key.decrypt(aes_bytes, get_oaep_padding())
		print(aes_bytes)
		iv_bytes = private_key.decrypt(iv_bytes, get_oaep_padding())
		print(iv_bytes)

		cipher = Cipher(algorithms.AES(aes_bytes), modes.CBC(iv_bytes), backend=default_backend())
		decr = cipher.decryptor()
		data = decr.update(encr_data) + decr.finalize()

		unpadder = padding.PKCS7(128).unpadder()

		return data
	# return unpadder.update(data) + unpadder.finalize()
	except ValueError:
		print()	

#Print keys
def print_all_keys():
	keys = read_private_keys();
	if keys != []:	
		for i in keys:
			print(i)

#Return OAEP padding for RSA keys
def get_oaep_padding():
	from cryptography.hazmat.primitives.asymmetric import padding
	oaep = padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	return oaep

#Request data from server
def request_data(url, public_key):
	public_key_bytes = public_key.public_bytes(
		encoding=serialization.Encoding.DER,
		format=serialization.PublicFormat.SubjectPublicKeyInfo)

	b64_public_key = (base64.b64encode(public_key_bytes)).decode('utf8')

	header = {'key' : json.dumps(b64_public_key)}

	response = requests.get(url, headers=header)

	return base64.b64decode(response.content)

#Send data to the server
def send_data(url, data, public_key):
	public_key_bytes = public_key.public_bytes(
		encoding=serialization.Encoding.DER,
		format=serialization.PublicFormat.SubjectPublicKeyInfo)

	b64_public_key = (base64.b64encode(public_key_bytes)).decode('utf8')
	header = {'key' : json.dumps(b64_public_key)}

	b64_data = base64.b64encode(bytes(data))


	response = requests.post(url, b64_data, headers=header)
	return response

#Restore the data if it was encrypted with AES
def restore_data(encr_server_response, private_key):
	encr_aes = []
	encr_iv = []
	encr_data = []

	encr_aes = encr_server_response[:256]
	encr_iv = encr_server_response[256:512]
	encr_data = encr_server_response[512:]

	aes_bytes = private_key.decrypt(
		encr_aes,
		get_oaep_padding()
	)

	iv_bytes = private_key.decrypt(
		encr_iv,
		get_oaep_padding()
	)

	cipher = Cipher(algorithms.AES(aes_bytes), modes.CBC(iv_bytes), backend=default_backend())
	decr = cipher.decryptor()
	data = decr.update(encr_data) + decr.finalize()

	unpadder = padding.PKCS7(128).unpadder()

	return unpadder.update(data) + unpadder.finalize()

#Encrypt data with aes key
def encrypt_data(data):
	json_data_bytes = (json.dumps(data)).encode('utf-8')

	server_public_key = request_spk()
	secret_key = os.urandom(16)
	iv = os.urandom(16)

	cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
	encr = cipher.encryptor()
	padder = padding.PKCS7(128).padder()
	
	json_data_bytes_pad = padder.update(json_data_bytes) + padder.finalize()
	encr_data = encr.update(json_data_bytes_pad) + encr.finalize()

	encr_aes = server_public_key.encrypt(
		secret_key,
		get_oaep_padding()
	)

	encr_iv = server_public_key.encrypt(
		iv,
		get_oaep_padding()
	)
		
	aes_iv_data = []

	index = 0

	while index < 256:
		aes_iv_data.append(encr_aes[index])
		index += 1;
	while index < 512:
		aes_iv_data.append(encr_iv[index-256])
		index += 1;
	while index < (512+len(encr_data)):
		aes_iv_data.append(encr_data[index-512])
		index += 1;	

	return aes_iv_data

#SPK - server public key
def request_spk():
	key = read_private_keys()

	if key != []:
		private_key = key[len(key)-1]
		encr_server_public_key = request_data('http://localhost:8080/getServerPublicKey', private_key.public_key())

		server_public_key_bytes = restore_data(encr_server_public_key, private_key)

		return serialization.load_der_public_key(bytes(server_public_key_bytes), backend=default_backend())
	else:
		print("No keys. Generate it by use 'generate-key-pair'")

#Request price lsit
def request_price_list():
	key = read_private_keys()

	if key != []:
		private_key = key[len(key)-1]
		encr_price_list = request_data('http://localhost:8080/getProducts', private_key.public_key())

		return bytes(restore_data(encr_price_list, private_key))
	else:
		print("No keys. Generate it by use 'generate-key-pair'")

#Send order list
def send_order_list(names, amount):
	if len(names) == len(amount):
		key = read_private_keys()

		if key != []:
			price_list = json.loads((request_price_list()).decode('utf-8'))
			wrong_products = False

			#Check parameters names
			for name in names:
				if wrong_products == False:
					wrong_products = True
					for product in price_list:
						if name == product.get('name'):
							wrong_products = False
							break

			if wrong_products == False:
				order_list = []
				index = 0

				#Add amount
				for name in names:
					for product in price_list:
						if name == product.get('name'):
							product['amount'] = amount[index]
							index += 1
							break

				#Form order list
				for product in price_list:
					if product.get('amount') != None:
						order_list.append(product)

				encr_data = encrypt_data(order_list)
				return send_data('http://localhost:8080/setOrder', encr_data, key[len(key)-1].public_key())
			else:
				print("This products doesn't exist. Check price list")
		else:
			print("No keys. Generate it by use 'generate-key-pair'")
	else:
		print("Numbers of the name parameters isn't equals amount parameters")

#Request order list
def request_order_list():
	keys = read_private_keys()

	if keys != []:
		private_key = keys[len(keys)-1]
		encr_orders = request_data('http://localhost:8080/getOrder', private_key.public_key())
		
		position = 0

		while position < len(encr_orders):
			length = int(private_key.decrypt(encr_orders[512+position:768+position], get_oaep_padding()))

			aes_bytes = encr_orders[position:256+position]
			iv_bytes = encr_orders[position+256:512+position]
			encr_data = encr_orders[position+512:length+position]

			for key in keys:
				print(decrypt_data(key, aes_bytes, iv_bytes, encr_data))

			position += 512 + length

	else:
		print("No keys. Generate it by use 'generate-key-pair'")



#Main menthod(used to parse command)
if __name__ == '__main__':
    parser = create_parser()
    namespace = parser.parse_args()

    if namespace.command == 'generate-key-pair':
        generate_key_pair()

    elif namespace.command == 'print-all-keys':
    	print_all_keys();

    elif namespace.command == 'request-SPK':
        response = request_spk()
        print(response)

    elif namespace.command == 'request-price-list':
    	response = request_price_list()
    	print(response.decode('utf-8'))

    elif namespace.command == 'send-order':
    	response = send_order_list(namespace.name, namespace.amount)
    	if(response.status_code == 200):
    		print("OK")
    	else:
    		print("Error " + str(response.status_code))
    elif namespace.command == 'print-all-orders':
    	response = request_order_list()    	