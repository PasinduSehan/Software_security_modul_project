from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

class KeyFactory:

    @staticmethod
    def encrypt_message(message, public_key_path):
        with open(public_key_path, "rb") as pub_file:
            public_key = serialization.load_pem_public_key(pub_file.read())
        
        # Generate a random Triple DES key
        triple_des_key = get_random_bytes(24)  # Triple DES key should be 24 bytes

        # Generate a random IV for CBC mode (8 bytes for Triple DES)
        iv = get_random_bytes(8)  # Triple DES block size is 8 bytes
        
        # Encrypt message using Triple DES with CBC mode
        cipher_3des = Cipher(algorithms.TripleDES(triple_des_key), modes.CBC(iv))
        encryptor = cipher_3des.encryptor()
        padded_message = pad(message.encode('utf-8'), algorithms.TripleDES.block_size)
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()

        # Encrypt Triple DES key using ECC (replace with your actual ECC encryption method)
        # This is a placeholder for ECC key exchange. Adjust as necessary.
        enc_key = base64.b64encode(triple_des_key).decode('utf-8')

        return {
            'enc_key': enc_key,
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    @staticmethod
    def decrypt_message(encrypted_data, private_key_path):
        with open(private_key_path, "rb") as priv_file:
            private_key = serialization.load_pem_private_key(priv_file.read(), password=None)
        
        enc_key = base64.b64decode(encrypted_data['enc_key'])
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])

        # Decrypt Triple DES key using ECC (replace with your actual ECC decryption method)
        # This is a placeholder for ECC key exchange. Adjust as necessary.
        triple_des_key = enc_key

        # Decrypt message using Triple DES with CBC mode
        cipher_3des = Cipher(algorithms.TripleDES(triple_des_key), modes.CBC(iv))
        decryptor = cipher_3des.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_message = unpad(padded_message, algorithms.TripleDES.block_size).decode('utf-8')

        return decrypted_message
