import json
import base64
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv
import os

load_dotenv()  # This reads the .env file into os.environ

# AES Key from environment
base64_key = os.getenv("AES_KEY")
if not base64_key:
    raise ValueError("AES_KEY not found in environment variables")

AES_KEY = binascii.unhexlify(base64_key)
print('aes key',AES_KEY)
# URL-safe Base64 encoding and decoding functions
def safe_encode(data):
    encoded = base64.urlsafe_b64encode(data).decode('utf-8')
    return encoded.replace('=', '')  # Strip '=' padding for compactness

def safe_decode(data):
    padded_data = data + '=' * ((4 - len(data) % 4) % 4)  # Re-add '=' padding
    return base64.urlsafe_b64decode(padded_data)

# AES Encryption
def encrypt_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext_padded = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(plaintext_padded)
    return safe_encode(ciphertext)

# AES Decryption
def decrypt_aes(key, encrypted_data):
    try:
        encrypted_data = safe_decode(encrypted_data)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data.decode()
    except (ValueError, KeyError) as e:
        print(f"Error during decryption: {e}")
        return None

# Validate JSON
def is_valid_json(data):
    try:
        json.loads(data)
        return True
    except json.JSONDecodeError:
        return False

# Main function for testing
def main():
    # Take JSON input from user
    json_input = input("Enter JSON data to encrypt: ")

    # Validate input
    if not is_valid_json(json_input):
        print("Invalid JSON input. Please provide valid JSON.")
        return

    # Encrypt the JSON input
    encrypted_data = encrypt_aes(AES_KEY, json_input)
    print(f"Encrypted data: {encrypted_data}")

    # Decrypt the data for verification
    decrypted_data = decrypt_aes(AES_KEY, encrypted_data)
    print(f"Decrypted data: {decrypted_data}")

    # Parse decrypted data as JSON
    try:
        data = json.loads(decrypted_data)
        print(f"Parsed data: {data}")
    except json.JSONDecodeError:
        print("Failed to parse decrypted data as JSON")

if __name__ == "__main__":
    main()