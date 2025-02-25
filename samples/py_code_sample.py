from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

def des_ecb_vulnerability():
    key = b'8bytekey'  # DES requires an 8-byte key
    cipher = DES.new(key, DES.MODE_ECB)  # ECB mode is insecure
    plaintext = b'SensitiveData'

    # Pad plaintext to a multiple of the block size
    padded_plaintext = plaintext.ljust(16, b'\x00')

    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)
    print(f"Encrypted Data (DES + ECB): {ciphertext}")

    # Decrypt
    decrypted = cipher.decrypt(ciphertext).rstrip(b'\x00')
    print(f"Decrypted Data: {decrypted}")

if __name__ == "__main__":
    des_ecb_vulnerability()
