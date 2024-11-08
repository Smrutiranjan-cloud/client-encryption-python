from mastercard.client_encryption.field_level_encryption import FieldLevelEncryption
import json

# Load the public key from PEM file for encryption
with open("public_key.pem", "rb") as public_file:
    public_key_data = public_file.read()

# Initialize the FieldLevelEncryption with the loaded public key
field_encryption = FieldLevelEncryption(public_key=public_key_data)

# Sensitive data to encrypt
credit_card_number = "4111111111111111".encode()

# Encrypt the credit card number
encrypted_data = field_encryption.encrypt(credit_card_number)

# Get additional values for JSON output
encrypted_key = field_encryption.get_encrypted_key()
iv = field_encryption.get_iv().hex()

# Prepare JSON format output
output = {
    "iv": iv,
    "encryptedKey": encrypted_key.hex(),
    "encryptedValue": encrypted_data.hex(),
    "oaepPaddingDigestAlgorithm": "SHA512"
}

# Print encrypted output
print(json.dumps(output, indent=4))
