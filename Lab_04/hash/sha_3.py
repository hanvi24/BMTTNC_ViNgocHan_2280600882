from Crypto.Hash import SHA3_256

def sha3(message):
    sh3_hash = SHA3_256.new()
    sh3_hash.update(message)
    return sh3_hash.digest()

def main():
    text = input("Nhap chuoi van ban: ").encode('utf-8')
    hashed_text = sha3(text)
    
    print("Chuoi van ban da nhap: ", text.decode('utf-8'))
    print("SHA-3 Hash: ", hashed_text.hex())
    
if __name__ == "__main__":
    main()