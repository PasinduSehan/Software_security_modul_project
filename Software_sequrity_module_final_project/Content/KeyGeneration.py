from Crypto.PublicKey import ECC
import hashlib

class KeyGeneration:

    @staticmethod
    def generate_ecc_keys():
        # Generate ECC private and public keys
        key = ECC.generate(curve='P-256')
        private_key = key.export_key(format='PEM')
        public_key = key.public_key().export_key(format='PEM')

        # Ensure keys are written as bytes by encoding the strings
        with open("private_key.pem", "wb") as priv_file:
            priv_file.write(private_key.encode('utf-8'))  # Convert to bytes

        with open("public_key.pem", "wb") as pub_file:
            pub_file.write(public_key.encode('utf-8'))  # Convert to bytes

        return private_key, public_key

    @staticmethod
    def hash_password(password):
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        return hashed_password

if __name__ == "__main__":
    private_key, public_key = KeyGeneration.generate_ecc_keys()
    print("ECC Keys generated and saved to files.")
