from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from web3 import Web3
import json
import base64
import os

# Generate RSA key pair for the recipient
recipient_key_pair = RSA.generate(2048)

# Save recipient's public key to a file
recipient_public_key = recipient_key_pair.publickey().export_key()
with open("recipient_public_key.pem", "wb") as file:
    file.write(recipient_public_key)

# Save recipient's private key to a file (for later decryption)
recipient_private_key = recipient_key_pair.export_key()
with open("recipient_private_key.pem", "wb") as file:
    file.write(recipient_private_key)

# Read data from CSV file
with open('Data/data.csv', 'rb') as file:
    data = file.read()

# Generate AES key
aes_key = get_random_bytes(16)  # AES-128

# Encrypt data using AES key
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
nonce = cipher_aes.nonce
ciphertext, tag = cipher_aes.encrypt_and_digest(data)

# Concatenate nonce, tag, and ciphertext
encrypted_data = nonce + tag + ciphertext

# Save the AES encrypted data to a file
with open("Data/encrypted_data.txt", "wb") as file:
    file.write(encrypted_data)

# Encrypt the AES key using recipient's RSA public key
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(recipient_public_key))
encrypted_aes_key = cipher_rsa.encrypt(aes_key)

# Encode encrypted data and key to base64 to store as strings
encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')
encrypted_aes_key_base64 = base64.b64encode(encrypted_aes_key).decode('utf-8')

# Connect to local blockchain
web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
assert web3.is_connected(), "Failed to connect to the local blockchain"

# Get the contract ABI and address
with open('build/contracts/EncryptedStorage.json') as f:
    contract_json = json.load(f)
    contract_abi = contract_json['abi']

contract_address = "0x1A744F31e77d54f8265DC3FEB75c3BAB4DD8418F"

# Get the contract instance
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

# Replace with the account that deployed the contract
account = web3.eth.accounts[0]

tx_hash = contract.functions.storeData(encrypted_data_base64, encrypted_aes_key_base64).transact({'from': account})
web3.eth.wait_for_transaction_receipt(tx_hash)

print("Data encrypted and stored on the blockchain.")
print("Transaction hash: " + tx_hash.hex())
