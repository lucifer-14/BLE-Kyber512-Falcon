from pqcrypto.sign import falcon_1024

# Generate key pair
public_key, secret_key = falcon_1024.generate_keypair()

message = b"Hello, Falcon!"

# Sign the message
signature = falcon_1024.sign(secret_key, message)

# Verify the signature
valid = falcon_1024.verify(public_key, message, signature)

print("Signature valid:", valid)  # Should print True