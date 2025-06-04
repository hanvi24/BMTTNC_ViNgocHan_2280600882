from flask import Flask, request, jsonify
from cipher.rsa.rsa_cipher import RSACipher

app = Flask(__name__)
rsa_cipher = RSACipher()

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    try:
        rsa_cipher.generate_keys()
        return jsonify({"message": "Keys generated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    try:
        data = request.json
        plain_text = data['message']
        key_type = data['key_type']
        private_key, public_key = rsa_cipher.load_keys()
        key = public_key if key_type == 'public' else private_key
        if key_type not in ['public', 'private']:
            return jsonify({'error': 'Invalid key type specified'}), 400
        encrypted_message = rsa_cipher.encrypt(plain_text, key)
        encrypted_hex = encrypted_message.hex()
        return jsonify({'encrypted_message': encrypted_hex})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    try:
        data = request.json
        encrypted_hex = data['ciphertext']  # Dữ liệu từ giao diện là hex
        key_type = data['key_type']
        private_key, public_key = rsa_cipher.load_keys()
        key = private_key if key_type == 'private' else public_key
        if key_type not in ['public', 'private']:
            return jsonify({'error': 'Invalid key type specified'}), 400
        encrypted_message = bytes.fromhex(encrypted_hex)  # Chuyển hex thành bytes
        decrypted_message = rsa_cipher.decrypt(encrypted_message, key)
        if not decrypted_message:
            return jsonify({'error': 'Decryption failed'}), 400
        return jsonify({'decrypted_message': decrypted_message})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign():
    try:
        data = request.json
        message = data['message']
        private_key, _ = rsa_cipher.load_keys()
        signature = rsa_cipher.sign(message, private_key)
        signature_hex = signature.hex()
        return jsonify({'signature': signature_hex})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify():
    try:
        data = request.json
        message = data['message']
        signature_hex = data['signature']
        _, public_key = rsa_cipher.load_keys()
        signature = bytes.fromhex(signature_hex)
        is_verified = rsa_cipher.verify(message, signature, public_key)
        return jsonify({'is_verified': is_verified})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)