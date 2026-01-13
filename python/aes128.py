def aes_encrypt(plaintext, key):
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes long for AES-128.")