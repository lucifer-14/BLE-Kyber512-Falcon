from pqcrypto.kem.ml_kem_512 import encrypt, decrypt, generate_keypair

public_key, secret_key = generate_keypair()
print(len(public_key))
print(len(secret_key))
print(type(secret_key))

ciphertext, shared_secret_sender = encrypt(public_key)

print("Ciphertext: ", len(ciphertext))
print("Shared Secret: ", len(shared_secret_sender))

shared_secret_receiver = decrypt(secret_key, ciphertext)

print("Sender's shared secret:  ", shared_secret_sender.hex())
print("Receiver's shared secret:", shared_secret_receiver.hex())
print("Match:", shared_secret_sender == shared_secret_receiver)