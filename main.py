
import time
import hashlib
import base64
import random

# pip3 install cryptography
from cryptography.fernet import Fernet


class Block:
    def __init__(self, index, data, prev_hash):
        self.index = index
        self.timestamp = int(time.time())
        self.data = data
        self.prev_hash = prev_hash
        self.hash = None
        self.nonce = 0
    def make_hash(self, prefix0s):
        payload = self.get_b64_encoded(self.data)
        while self.hash is None:
            whole_string = str.format("index: {} timestamp: {} data: {} prev_hash: {} nonce: {}",
                self.index, self.timestamp, payload, self.prev_hash, self.nonce)
            generated_hash = hashlib.sha256(whole_string.encode("UTF-8")).hexdigest()
            if generated_hash[:prefix0s] == "0"*prefix0s:
                self.hash = generated_hash
                break
            self.nonce += 1
    def get_b64_encoded(self, data):
        data_bytes = data.encode("UTF-8")
        return base64.b64encode(data_bytes).decode("UTF-8")
    def get_hash(self):
        return self.hash
    def __repr__(self):
        return str.format("Block {} [data: {} timestamp: {} hash:{} prev_hash: {}]",
            self.index, self.data, self.timestamp, self.hash, self.prev_hash)


class Main:
    def __init__(self):
        self.blocks = []
        self.last_block = 0
        self.prefix0s = 1
        self.master_password = None
        self.cipher_suite = None
        self.initiate()
    def initiate(self):
        self.master_password = input("Enter master password: ")
        hash_key = base64.urlsafe_b64encode(hashlib.sha256(self.master_password.encode("UTF-8")).digest())
        self.cipher_suite = Fernet(hash_key)
    def enc_payload(self, data):
        encoded = data.encode("UTF-8")
        encrypted_bytes = self.cipher_suite.encrypt(encoded)
        random_iv = "".join([chr(random.randint(65, 123)) for i in range(16)])
        return random_iv + encrypted_bytes.decode("UTF-8")
    def dec_data(self, enc):
        enc_bytes = enc[16:].encode("UTF-8")
        return self.cipher_suite.decrypt(enc_bytes).decode("UTF-8")
    def add_a_block(self, data):
        index = len(self.blocks)
        block = Block(index, data, self.last_block)
        block.make_hash(self.prefix0s)
        self.blocks.append(block)
        self.last_block = block.get_hash()
    def lookup(self, key):
        for block in self.blocks:
            data = self.dec_data(block.data)
            if key+":" in data:
                return data
        return "NOT FOUND"
    def run(self):
        while True:
            data = input("Enter data (like key:password) to be added into blockchain (Enter 'X' if you want to close): ")
            if data == "X":
                for block in self.blocks:
                    print (block)
                break
            else:
                enc_data = self.enc_payload(data)
                self.add_a_block(enc_data)


if __name__ == "__main__":
    main = Main()
    main.run()


