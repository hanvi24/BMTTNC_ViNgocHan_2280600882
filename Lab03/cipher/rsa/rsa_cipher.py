import rsa, os

if not os.path.exists('cipher/rsa/keys'):
    os.makedirs('cipher/rsa/keys')

class RSACipher:
    def __init__(self):
        pass

    def generate_keys(self):
        (public_key, private_key) = rsa.newkeys(1024)
        with open('cipher/rsa/keys/publicKey.pem', 'wb') as p:
            p.write(public_key.save_pkcs1('PEM'))
        with open('cipher/rsa/keys/privateKey.pem', 'wb') as p:
            p.write(private_key.save_pkcs1('PEM'))

    def load_keys(self):
        try:
            with open('cipher/rsa/keys/publicKey.pem', 'rb') as p:
                public_key = rsa.PublicKey.load_pkcs1(p.read())
            with open('cipher/rsa/keys/privateKey.pem', 'rb') as p:
                private_key = rsa.PrivateKey.load_pkcs1(p.read())
            return private_key, public_key
        except FileNotFoundError:
            raise Exception("Keys not found. Please generate keys first.")

    def encrypt(self, message, key):
        try:
            return rsa.encrypt(message.encode('ascii'), key)
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    def decrypt(self, ciphertext, key):
        try:
            return rsa.decrypt(ciphertext, key).decode('ascii')
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

    def sign(self, message, key):
        try:
            return rsa.sign(message.encode('ascii'), key, 'SHA-1')
        except Exception as e:
            raise Exception(f"Signing failed: {str(e)}")

    def verify(self, message, signature, key):
        try:
            return rsa.verify(message.encode('ascii'), signature, key) == 'SHA-1'
        except Exception as e:
            raise Exception(f"Verification failed: {str(e)}")