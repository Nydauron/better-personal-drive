from config import JWT_PRIV_FILE, JWT_PUB_FILE

def load_jwt_private_key():
    # Should create some error if it cant find private key file
    with open(JWT_PRIV_FILE, 'r') as f:
        buf = f.read()
        print("Loaded priv key")
    return buf
        
def load_jwt_public_key():
    # Should create some error if it cant find public key file
    with open(JWT_PUB_FILE, 'r') as f:
        buf = f.read()
        print("Loaded pub key")
    return buf
    
JWT_PRIV_KEY = load_jwt_private_key()
JWT_PUB_KEY = load_jwt_public_key()
JWT_STOR_KEY = load_jwt_private_key()