import json
from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig
from client_encryption.field_level_encryption import encrypt_payload, decrypt_payload

# Step 1: Define the FieldLevelEncryptionConfig directly
config = FieldLevelEncryptionConfig(
    encryption_path='$.credit_card.number',
    encrypted_value_field_name='encryptedValue',
    iv_field_name='iv',
    oaep_padding_digest_algorithm='SHA-512',
    encrypted_key_field_name='encryptedKey',
    public_key_fingerprint_field_name='publicKeyFingerprint',
    encryption_certificate_path='path_to_your_public_key.pem',
    encryption_key_fingerprint="80810fc13a8319fcf0e2e(...)82cc3ce671176343cfe8160c2279",
    decryption_path='$.encrypted_data.encryptedValue',
    decryption_key_path='path_to_your_private_key.pem'
)

# Step 2: Sample payload with sensitive data to encrypt
payload = {
    "credit_card": {
        "number": "4111111111111111",
        "expiry": "12/25"
    },
    "customer": {
        "name": "John Doe",
        "address": "1234 Elm Street"
    }
}

# Step 3: Encrypt the payload
encrypted_payload = encrypt_payload(payload, config)
print("Encrypted Payload:", json.dumps(encrypted_payload, indent=4))

# Step 4: Decrypt the payload to retrieve original data
decrypted_payload = decrypt_payload(encrypted_payload, config)
print("Decrypted Payload:", json.dumps(decrypted_payload, indent=4))
