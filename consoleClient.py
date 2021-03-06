import sys, argparse, requests, base64, struct, json, pem, os, struct
from cryptography.hazmat.backends import default_backend, interfaces
from cryptography.hazmat.primitives.asymmetric import rsa, utils
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

	send_update_parser = subparsers.add_parser('send-update')
	send_update_parser.add_argument('--name', '-n', nargs='+')
	send_update_parser.add_argument('--amount', '-a', nargs='+')

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

#Create sign
def generate_sign(private_key):
	from cryptography.hazmat.primitives.asymmetric import padding

	sign = private_key.sign(
		b'key',
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=128
		),
		hashes.SHA256()
	)
	return sign

#Decrypt data
def decrypt_data(private_key, aes_bytes, iv_bytes, encr_data):
	try:
		aes_bytes = private_key.decrypt(aes_bytes, get_oaep_padding())
		iv_bytes = private_key.decrypt(iv_bytes, get_oaep_padding())

		cipher = Cipher(algorithms.AES(aes_bytes), modes.CBC(iv_bytes), backend=default_backend())
		decr = cipher.decryptor()
		data = decr.update(encr_data) + decr.finalize()

		unpadder = padding.PKCS7(128).unpadder()

		return unpadder.update(data) + unpadder.finalize()
	except ValueError:
		pass
			
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
def send_data(url, data, private_key, update):
	public_key_bytes = private_key.public_key().public_bytes(
		encoding=serialization.Encoding.DER,
		format=serialization.PublicFormat.SubjectPublicKeyInfo)

	b64_public_key = (base64.b64encode(public_key_bytes)).decode('utf8')
	header = {'key' : json.dumps(b64_public_key)}

	b64_data = base64.b64encode(bytes(data))

	if update:
		response = requests.post(url, b64_data, headers=header)
		if response.status_code == 200:
			keys = read_private_keys()
			public_keys = []

			for key in keys:
				public = key.public_key().public_bytes(
					encoding=serialization.Encoding.DER,
					format=serialization.PublicFormat.SubjectPublicKeyInfo
				)
				if(public_key_bytes != public):
					public_keys.append((base64.b64encode(public)).decode('utf8'))

			encr_keys = encrypt_data(public_keys, True, private_key)

			requests.post('http://localhost:8080/deleteUsers', base64.b64encode(bytes(encr_keys)), headers=header)
	else:
		print(b64_data);
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
def encrypt_data(data, update, private_key):
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

	aes_iv_data.extend(encr_aes)
	aes_iv_data.extend(encr_iv)
	aes_iv_data.extend(encr_data)

	if update:
		aes_iv_data.extend(generate_sign(private_key))

	return aes_iv_data

#SPK - server public key
def request_spk():
	key = read_private_keys()

	if key != []:
		private_key = key[len(key)-1]
		response = request_data('http://localhost:8080/getServerPublicKey', private_key.public_key())

		return serialization.load_der_public_key(bytes(response), backend=default_backend())
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
def send_order_list(url, names, amount, update):
	if len(names) == len(amount):
		key = read_private_keys()

		if key != []:
			price_list = json.loads((request_price_list()).decode('utf-8'))
			private_key = key[len(key)-1]
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

				if update:
					resp = request_order_list()

					for d in order_list:
						for r in resp:
							if r['name'] == d['name']:
								r['amount'] = d['amount']
								break
					
					order_list = resp

				encr_data = encrypt_data(order_list, update, private_key)
				return send_data(url, encr_data, private_key, update)
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
		decr_data_list = []
		data = []

		while position < len(encr_orders):
			length = int(private_key.decrypt(encr_orders[512+position:768+position], get_oaep_padding()))


			aes_bytes = encr_orders[position:256+position]
			iv_bytes = encr_orders[position+256:512+position]
			encr_data = encr_orders[position+768:length+position+768]

			for key in keys:
				decr_data_bytes = decrypt_data(key, aes_bytes, iv_bytes, encr_data)
				if  decr_data_bytes != None:
					decr_data_list.extend(json.loads(decr_data_bytes))	

			position += 768 + length

		if decr_data_list != None:
			for order in decr_data_list:
				if data == []:
					data.append(order)
					continue
				else:
					index = 0
					while(index<len(data)):
						product = data[index]
						if product['name'] == order['name']:
							product['amount'] += order['amount']
							index += 1
							break
						elif index == len(data)-1:	
							data.append(order)
							index += 1
							break
						else:
							index += 1
		return data	
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
    	response = send_order_list('http://localhost:8080/setOrder', namespace.name, namespace.amount, False)
    	if(response.status_code == 200):
    		print("OK")
    	else:
    		print("Error " + str(response.status_code))

    elif namespace.command == 'print-all-orders':
    	response = request_order_list()
    	for order in response:
    		print(order)

    elif namespace.command == 'send-update':
    	response = send_order_list('http://localhost:8080/updateOrder', namespace.name, namespace.amount, True)
    	if(response.status_code == 200):
    		print("OK")
    	else:
    		print("Error " + str(response.status_code))