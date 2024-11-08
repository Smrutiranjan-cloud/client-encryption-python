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


############################
############################
from mastercard_encryption import FieldLevelEncryption, FieldLevelEncryptionConfig

# Define the encryption configuration directly
config = FieldLevelEncryptionConfig(
    encryption_path="$.credit_card.number",  # Path for data to be encrypted
    encrypted_value_field_path="$.encrypted_data.encryptedValue",  # Path where encrypted value will be placed
    encryption_certificate_path="path/to/your_public_certificate.pem",  # Path to your public certificate
    encryption_key_fingerprint="your_encryption_key_fingerprint",  # Key fingerprint
    decryption_path="$.encrypted_data.encryptedValue",  # Path for encrypted data in the payload
    decryption_key_path="path/to/your_private_key.pem",  # Path to your private key
    oaep_padding_digest_algorithm="SHA-512"  # Padding digest algorithm
)

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


################################
################################

from mastercard_encryption import FieldLevelEncryption, FieldLevelEncryptionConfig

# Create a FieldLevelEncryptionConfig instance
config = FieldLevelEncryptionConfig()

# Manually configure each required attribute
config.encryption_path = "$.credit_card.number"  # Path for the field to be encrypted
config.encrypted_value_field_path = "$.encrypted_data.encryptedValue"  # Path for placing the encrypted value
config.encryption_certificate_path = "path/to/your_public_certificate.pem"  # Path to the public key certificate
config.encryption_key_fingerprint = "your_encryption_key_fingerprint"  # Encryption key fingerprint
config.decryption_path = "$.encrypted_data.encryptedValue"  # Path to find encrypted data for decryption
config.decryption_key_path = "path/to/your_private_key.pem"  # Path to the private key for decryption
config.oaep_padding_digest_algorithm = "SHA-512"  # Padding digest algorithm

# Sample payload to be encrypted
payload = {
    "credit_card": {
        "number": "5555555555554444",
        "expiry": "12/23",
        "cvv": "123"
    },
    "other_data": "sample_value"
}

# Encrypt the payload using FieldLevelEncryption
encrypted_payload = FieldLevelEncryption.encrypt(payload, config)

print("Encrypted Payload:", encrypted_payload)

