import hashlib
import json
import os
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp.isoformat()}{self.data}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp.isoformat(),  # Convert datetime to string
            'data': {
                'nonce': self.data[0].hex(),  # Convert bytes to hex
                'ciphertext': self.data[1].hex(),  # Convert bytes to hex
                'tag': self.data[2].hex()  # Convert bytes to hex
            },
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, datetime.datetime.now(), (b'0', b'0', b'0'), '0')
        self.chain.append(genesis_block)

    def add_block(self, new_block):
        new_block.previous_hash = self.chain[-1].hash
        self.chain.append(new_block)
        self.save_to_file('blockchain.json')

    def save_to_file(self, filename):
        with open(filename, 'w') as f:
            blockchain_data = [block.to_dict() for block in self.chain]
            json.dump(blockchain_data, f)

    def load_from_file(self, filename):
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    blocks_data = json.load(f)
                    for block_data in blocks_data:
                        block = Block(
                            block_data['index'],
                            datetime.datetime.fromisoformat(block_data['timestamp']),
                            (
                                bytes.fromhex(block_data['data']['nonce']),
                                bytes.fromhex(block_data['data']['ciphertext']),
                                bytes.fromhex(block_data['data']['tag'])
                            ),
                            block_data['previous_hash'],
                            block_data['nonce']
                        )
                        self.chain.append(block)
            except json.JSONDecodeError as e:
                print("Error decoding JSON from file:", e)
                print("The file may be empty or corrupted.")

class VidyaCipher:
    def __init__(self):
        self.blockchain = Blockchain()

    def encrypt(self, plaintext, key):
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(pad(plaintext.encode(), AES.block_size))
        return cipher.nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag, key):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
        return decrypted.decode()

    def vidya_cipher_generate(self, base_number):
        key = hashlib.sha256(base_number.encode()).digest()  # Derive a 256-bit key
        nonce, ciphertext, tag = self.encrypt(base_number, key)
        new_block = Block(len(self.blockchain.chain), datetime.datetime.now(), (nonce, ciphertext, tag), self.blockchain.chain[-1].hash)
        self.blockchain.add_block(new_block)
        return ciphertext.hex()  # Return the encrypted number in hex

    def validate_vidya_number(self, base_number, ciphertext_hex):
        # Load blockchain data
        self.blockchain.load_from_file('blockchain.json')
        key = hashlib.sha256(base_number.encode()).digest()  # Derive the same key
        for block in self.blockchain.chain:
            if block.data[1].hex() == ciphertext_hex:  # Check if the ciphertext matches
                nonce, ciphertext, tag = block.data
                try:
                    decrypted_base_number = self.decrypt(nonce, ciphertext, tag, key)
                    if decrypted_base_number == base_number:
                        print(f"Validation successful: The base number '{base_number}' is correct.")
                    else:
                        print(f"Validation failed: The base number '{base_number}' does not match.")
                except Exception as e:
                    print("Decryption failed:", e)
                return
        print("No matching ciphertext found in the blockchain.")

def display_banner():
    print("=" * 60)
    print("         Welcome to Vidya Cipher Encryption Tool        ")
    print("     Developed by Prabal Manhas & Joydeep Chandra      ")
    print("             © 2024 All Rights Reserved       ")
    print("=" * 60)
    print("\n           BLOCKCHAIN BASED TOOL FOR\nENCRYPTION AND VALIDATION OF CREDIT CARD NUMBERS\n")

def main():
    display_banner()
    
    while True:
        print("MAIN MENU: ")
        print("1. GENERATE A VIDYA CIPHER NUMBER ---> ")
        print("2. VALIDATE VIDYA CIPHER NUMBER ---> ")
        print("3. EXIT PROGRAM")
        choice = input("\nENTER DESIRED CHOICE = ")
        
        vidya_cipher = VidyaCipher()
        # Load the blockchain from file (if exists)
        vidya_cipher.blockchain.load_from_file('blockchain.json')

        if choice == '1':
            base_number = input("ENTER THE BASE NUMBER YOU NEED TO ENCRYPT = ")
            vidya_number = vidya_cipher.vidya_cipher_generate(base_number)
            print(f"YOUR GENERATED VIDYA CIPHER NUMBER = {vidya_number}")
            input("\nPRESS AND KEY TO RETURN TO MAIN MENU...")

        elif choice == '2':
            base_number = input("ENTER THE BASE NUMBER TO VALIDATE = ")
            ciphertext_hex = input("ENTER YOU PREVIOUSLY GENERATED VIDYA CIPHER NUMBER FOR THE ABOVE BASE NUMBER = ")
            vidya_cipher.validate_vidya_number(base_number, ciphertext_hex)
            input("\nPRESS AND KEY TO RETURN TO MAIN MENU...")

        elif choice == '3':
            print("\nEXITING VIDYA CIPHER TOOL... GOODBYE!")
            break
        
        else:
            print("\nINVALID CHOICE! PLEASE TRY AGAIN...")
            input("\nPRESS AND KEY TO RETURN TO MAIN MENU...")

if __name__ == "__main__":
    main()