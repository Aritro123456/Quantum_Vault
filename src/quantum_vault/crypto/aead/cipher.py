from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key, nonce, plaintext, header):
    return AESGCM(key).encrypt(nonce, plaintext, header)


def decrypt(key, nonce, ciphertext, header):
    # Returns plaintext only after authentication succeeds.
    return AESGCM(key).decrypt(nonce, ciphertext, header)
