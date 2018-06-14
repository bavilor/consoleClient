import sys, argparse, requests, base64, struct, json, pem
from cryptography.hazmat.backends import default_backend, interfaces
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, keywrap

#Init command line parser
def createParser():	
	parser = argparse.ArgumentParser()
	subparsers = parser.add_subparsers(dest='command')

	generate_RSAkey_parser = subparsers.add_parser('generateKeyPair')
	request_SPK_parser = subparsers.add_parser('requestSPK')
	request_price_parser = subparsers.add_parser('requestPriceList')
	print_all_keys_parser = subparsers.add_parser('printAllKeys')

	return parser

#Create RSA private key
def generateKeyPair():
	#create privateKey
	privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

	#serialize it
	pem_key = privateKey.private_bytes(
 		encoding = serialization.Encoding.PEM,
 		format = serialization.PrivateFormat.PKCS8,
 		encryption_algorithm = serialization.BestAvailableEncryption(b'hellothere')
 		)

	#write in pem file
	with open('keyStore.pem', 'ab') as file:
		file.write(pem_key)
	print("Keys're generated")

	
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
				enc_pem = serialization.load_pem_private_key(bytes(key, 'utf-8'), password = b'hellothere', backend = default_backend())
				keys.append(enc_pem)
				key = ''
	except FileNotFoundError:
		print("No keys. Generate it by use 'generateKeyPair'")
	return keys


#Request price lsit
def requestPriceList():
	key = readPrivateKeys();
	encr_aes = []
	encr_iv = []
	encr_data = []

	if(key != []):
		public_key_obj = key[len(key) - 1].public_key();
		pem_public_key = public_key_obj.public_bytes(
			encoding = serialization.Encoding.DER,
			format = serialization.PublicFormat.SubjectPublicKeyInfo)

		b64_public_key = (base64.b64encode(pem_public_key)).decode('utf8')

		header = {'key' : json.dumps(b64_public_key)}

		response = requests.get('http://localhost:8080/getProducts', headers = header)
		decoded_response = base64.b64decode(response.content)

		index = 0
		while(index < 256):
			encr_aes.append(decoded_response[index])
			index += 1
	
		while(index < 512):
			encr_iv.append(decoded_response[index])
			index += 1

		while(index < len(decoded_response)):
			encr_data.append(decoded_response[index])
			index += 1

		decrypAESdata(encr_aes, encr_iv, encr_data, key)

		return 
	else:
		print("No keys. Generate it by use 'generateKeyPair'")

#decrypt aes data
def decrypAESdata(encr_aes, encr_iv, encr_data, private_key):
	backend = interfaces.CipherBackend
	aes_bytes = keywrap.aes_key_unwrap_with_padding(
		wrapping_key = encr_aes, 
		wrapped_key = private_key.private_bytes(), 
		backend = default_backend()
	)
	print(aes)


#Print keys
def printAllKeys():
	keys = readPrivateKeys();
	if(keys != []):	
		for i in keys:
			print(i)



#SPK - server public key
def requestSPK():
	return requests.get('http://localhost:8080/getServerPublicKey')

#Use PEM key with format: PUBLIC KEY, not with RSA PUBLIC KEY. PEM is: pref + base64(in java - key.getEncoded) + postf
def restoreSPK(b64key):
	pem_prefix = '-----BEGIN PUBLIC KEY-----\n'
	pem_postfix = '\n-----END PUBLIC KEY-----'
	pem_key = '{}{}{}'.format(pem_prefix, b64key, pem_postfix)
	encoded_pem_key = pem_key.encode('utf8')

	return serialization.load_pem_public_key(encoded_pem_key, backend=default_backend())

#Encode data by use SPK
def encodeSession(PSK, session):
	return PSK.encrypt(
		session.encode('utf8'), 
		padding.OAEP(
			mgf = padding.MGF1(algorithm = hashes.SHA256()),
			algorithm = hashes.SHA256(),
			label = None 
		)
	)

def sendUPK(data):
	b64 = base64.b64encode(data)

	request = requests.post('http://localhost:8080/getServerPublicKey', b64)
	print(request.text)

#Main menthod(used to parse command)
if __name__ == '__main__':
    parser = createParser()
    namespace = parser.parse_args()

    if namespace.command == "generateKeyPair":
        generateKeyPair()

    elif namespace.command == 'printAllKeys':
    	printAllKeys();

    elif namespace.command == "requestSPK":
        response = requestSPK()
        print(response.text)
        key = restoreSPK(response.text)

    elif namespace.command == 'requestPriceList':
    	response = requestPriceList()
    	# print(response.content)