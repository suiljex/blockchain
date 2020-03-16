import json
import secrets
import ecdsa
import hashlib


class BlockchainCrypto():
    @staticmethod
    def valid_proof(last_hash, nonce, difficulty):
        guess = f'{last_hash}{nonce}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        guess_hash_int = int(guess_hash, base=16)
        return guess_hash_int < pow(2, 256 - difficulty)

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def generate_private_key():
        bits = secrets.randbits(256)
        bits_hex = hex(bits)
        private_key = bits_hex[2:]
        return private_key

    @staticmethod
    def generate_public_key(private_key):
        private_key_bytes = bytes.fromhex(private_key)
        public_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        public_key_bytes = public_key.to_string()
        public_key_hex = public_key_bytes.hex()
        return public_key_hex

    @staticmethod
    def generate_address(public_key):
        public_key_bytes = bytes.fromhex(public_key)
        address_hash = hashlib.sha256(public_key_bytes)
        address = address_hash.hexdigest()
        return address

    @staticmethod
    def sign(message, private_key):
        private_key_bytes = bytes.fromhex(private_key)
        message_bytes = bytes(message, "ascii")
        private_key_ready = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        signature_bytes = private_key_ready.sign(message_bytes)
        signature = signature_bytes.hex()
        return signature

    @staticmethod
    def verify(message, signature, public_key):
        public_key_bytes = bytes.fromhex(public_key)
        message_bytes = bytes(message, "ascii")
        public_key_ready = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
        try:
            result = public_key_ready.verify(bytes.fromhex(signature), message_bytes)
        except ecdsa.keys.BadSignatureError:
            result = False
        return result

    @staticmethod
    def calculate_difficulty(hight):
        return hight

    @staticmethod
    def calculate_reward(difficulty):
        return 1


if __name__ == '__main__':
    print("This module is a dependecy")
    exit(0)
