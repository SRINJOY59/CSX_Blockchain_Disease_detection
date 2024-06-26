from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from web3 import Web3
import json
import base64

# Read recipient's private key from PEM file
with open("recipient_private_key.pem", "rb") as file:
    recipient_private_key_pem = file.read()
recipient_private_key = RSA.import_key(recipient_private_key_pem)

# Connect to the local blockchain
web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
assert web3.is_connected(), "Failed to connect to the local blockchain"

# Load the contract ABI and address
with open('build/contracts/EncryptedStorage.json') as f:
    contract_json = json.load(f)
    contract_abi = contract_json['abi']

contract_address = "0x1A744F31e77d54f8265DC3FEB75c3BAB4DD8418F"  # Replace with your deployed contract address

# Get the contract instance
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

# Get the account to interact with the contract
account = web3.eth.accounts[0]  # Replace with your account address

# Retrieve encrypted data and key from the contract
retrieved_data_base64, retrieved_key_base64 = contract.functions.retrieveData().call({'from': account})

# Decode base64 encoded data and key
retrieved_data = base64.b64decode(retrieved_data_base64)
retrieved_key = base64.b64decode(retrieved_key_base64)

# Decrypt the AES key using recipient's RSA private key
cipher_rsa = PKCS1_OAEP.new(recipient_private_key)
try:
    aes_key = cipher_rsa.decrypt(retrieved_key)
except ValueError as e:
    print(f"Error decrypting AES key: {e}")
    exit(1)

# Decrypt the data using AES key
nonce = retrieved_data[:16]
tag = retrieved_data[16:32]
ciphertext = retrieved_data[32:]
cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
try:
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
except ValueError as e:
    print(f"Error decrypting data: {e}")
    exit(1)

# Save the decrypted data to a file
with open("Data/decrypted_data.csv", "wb") as file:
    file.write(decrypted_data)

print("Data decrypted successfully.")

