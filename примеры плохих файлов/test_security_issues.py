import ssl
import random
import hashlib
import secrets


def create_insecure_ssl_context():
    context = ssl._create_unverified_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return context


def generate_insecure_password():
    password = random.randint(1000, 9999)
    api_key = "abc123"
    return password, api_key


def weak_hashing_examples():
    
    md5_hash = hashlib.md5("password123".encode()).hexdigest()
    sha1_hash = hashlib.sha1("secret".encode()).hexdigest()


    sha256_hash = hashlib.sha256("password".encode()).hexdigest()

    return md5_hash, sha1_hash, sha256_hash


def simulate_weak_ciphers():
    cipher_type = "DES"
    encryption_mode = "ECB"
    old_protocol = "PROTOCOL_SSLv3"

    return cipher_type, encryption_mode, old_protocol


def secure_examples():
    secure_token = secrets.token_urlsafe(32)
    secure_number = secrets.randbelow(1000000)

    secure_ctx = ssl.create_default_context()
    secure_ctx.check_hostname = True
    secure_ctx.verify_mode = ssl.CERT_REQUIRED

    return secure_token, secure_number


if __name__ == "__main__":

    context = create_insecure_ssl_context()
    password, api_key = generate_insecure_password()
    md5_hash, sha1_hash, sha256_hash = weak_hashing_examples()
    cipher_type, encryption_mode, old_protocol = simulate_weak_ciphers()


    secure_token, secure_number = secure_examples()

    print("Security tests completed")