from flask import Flask, render_template, request, redirect, url_for, flash
import hashlib
import json
import os
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this for production

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
            'timestamp': self.timestamp.isoformat(),
            'data': {
                'nonce': self.data[0].hex(),
                'ciphertext': self.data[1].hex(),
                'tag': self.data[2].hex()
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
                    self.chain = []  # Clear current chain before loading
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
        key = hashlib.sha256(base_number.encode()).digest()
        nonce, ciphertext, tag = self.encrypt(base_number, key)
        new_block = Block(len(self.blockchain.chain), datetime.datetime.now(), (nonce, ciphertext, tag), self.blockchain.chain[-1].hash)
        self.blockchain.add_block(new_block)
        return ciphertext.hex()

    def validate_vidya_number(self, base_number, ciphertext_hex):
        self.blockchain.load_from_file('blockchain.json')
        key = hashlib.sha256(base_number.encode()).digest()
        for block in self.blockchain.chain:
            if block.data[1].hex() == ciphertext_hex:
                nonce, ciphertext, tag = block.data
                try:
                    decrypted_base_number = self.decrypt(nonce, ciphertext, tag, key)
                    if decrypted_base_number == base_number:
                        return True, "Validation successful!"
                    else:
                        return False, "Validation failed: Base number doesn't match."
                except Exception as e:
                    return False, f"Decryption failed: {str(e)}"
        return False, "No matching ciphertext found in the blockchain."

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    if request.method == 'POST':
        base_number = request.form.get('base_number')
        if not base_number:
            flash('Please enter a base number', 'error')
            return redirect(url_for('generate'))
        
        vidya_cipher = VidyaCipher()
        vidya_cipher.blockchain.load_from_file('blockchain.json')
        try:
            vidya_number = vidya_cipher.vidya_cipher_generate(base_number)
            flash(f'Successfully generated Vidya Cipher Number: {vidya_number}', 'success')
            return render_template('generate.html', vidya_number=vidya_number)
        except Exception as e:
            flash(f'Error generating cipher: {str(e)}', 'error')
    
    return render_template('generate.html')

@app.route('/validate', methods=['GET', 'POST'])
def validate():
    if request.method == 'POST':
        base_number = request.form.get('base_number')
        ciphertext_hex = request.form.get('ciphertext_hex')
        
        if not base_number or not ciphertext_hex:
            flash('Please provide both base number and ciphertext', 'error')
            return redirect(url_for('validate'))
        
        vidya_cipher = VidyaCipher()
        vidya_cipher.blockchain.load_from_file('blockchain.json')
        
        is_valid, message = vidya_cipher.validate_vidya_number(base_number, ciphertext_hex)
        if is_valid:
            flash(message, 'success')
        else:
            flash(message, 'error')
        
        return render_template('validate.html', validation_result=message)
    
    return render_template('validate.html')

@app.route('/blockchain')
def view_blockchain():
    vidya_cipher = VidyaCipher()
    vidya_cipher.blockchain.load_from_file('blockchain.json')
    
    # Convert blocks to a format suitable for display
    blocks = []
    for block in vidya_cipher.blockchain.chain:
        block_dict = block.to_dict()
        # Format the timestamp for better readability
        block_dict['timestamp'] = datetime.datetime.fromisoformat(block_dict['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        blocks.append(block_dict)
    
    return render_template('blockchain.html', blocks=blocks)

if __name__ == '__main__':
    app.run(debug=True)