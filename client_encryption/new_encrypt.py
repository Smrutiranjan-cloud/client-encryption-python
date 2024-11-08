import json
from client_encryption.field_level_encryption_config import FieldLevelEncryptionConfig
from client_encryption.field_level_encryption import encrypt_payload, decrypt_payload

# Step 1: Define encryption configuration
config = FieldLevelEncryptionConfig.builder() \
    .with_encryption_path('$.credit_card.number', '$.encrypted_data.encryptedValue') \
    .with_encryption_key_fingerprint_path("$.encrypted_data.publicKeyFingerprint") \
    .with_encryption_certificate_path("path_to_your_public_key.pem") \
    .with_oaep_padding_digest_algorithm("SHA-512") \
    .with_decryption_path('$.encrypted_data.encryptedValue', '$.credit_card.number') \
    .with_decryption_key_path("path_to_your_private_key.pem") \
    .with_encryption_key_fingerprint("80810fc13a8319fcf0e2e(...)82cc3ce671176343cfe8160c2279") \
    .build()

# Sample payload with sensitive data to encrypt
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

# Step 2: Encrypt the payload
encrypted_payload = encrypt_payload(payload, config)
print("Encrypted Payload:", json.dumps(encrypted_payload, indent=4))

# Step 3: Decrypt the payload to retrieve original data
decrypted_payload = decrypt_payload(encrypted_payload, config)
print("Decrypted Payload:", json.dumps(decrypted_payload, indent=4))
