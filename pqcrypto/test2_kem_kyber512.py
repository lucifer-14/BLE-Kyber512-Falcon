from pqcrypto.kem import ml_kem_512

public_key, secret_key = ml_kem_512.generate_keypair()
print("Public key length:", len(public_key))  # should be fixed size
print("Secret key length:", len(secret_key))  # should be 1632

ciphertext, shared_secret_sender = ml_kem_512.encrypt(public_key)
shared_secret_receiver = ml_kem_512.decrypt(secret_key, ciphertext)


print("Shared secrets match:", shared_secret_sender == shared_secret_receiver)
