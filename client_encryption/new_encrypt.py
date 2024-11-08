from mastercard_encryption import FieldLevelEncryption, FieldLevelEncryptionConfig

# Define encryption configuration
config = FieldLevelEncryptionConfig.builder() \
    .with_encryption_path("$.credit_card.number", "$.encrypted_data.encryptedValue") \
    .with_encryption_certificate_path("path/to/your_public_certificate.pem") \
    .with_encryption_key_fingerprint("your_encryption_key_fingerprint") \
    .with_decryption_path("$.encrypted_data.encryptedValue", "$.credit_card.number") \
    .with_decryption_key_path("path/to/your_private_key.pem") \
    .with_oaep_padding_digest_algorithm("SHA-512") \
    .build()

# Sample payload to be encrypted
payload = {
    "credit_card": {
        "number": "5555555555554444",
        "expiry": "12/23",
        "cvv": "123"
    },
    "other_data": "sample_value"
}

# Encrypt the payload
encrypted_payload = FieldLevelEncryption.encrypt(payload, config)

print("Encrypted Payload:", encrypted_payload)
