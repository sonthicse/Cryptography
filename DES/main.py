import DES

if __name__ == "__main__":

    # Encryption
    with open("DES/plaintext.txt", "rb") as file:
        plaintext = file.read()
        
    with open("DES/key.txt", "rb") as file:
        key = file.read()

    print("Plaintext:", plaintext)
    print("Plaintext (hex):", plaintext.hex())
    print("Key:", key)
    print("Key (hex):", key.hex())

    ciphertext = DES.DES_encrypt(plaintext, key)
    print("Ciphertext:", ciphertext)
    print("Ciphertext (hex):", ciphertext.hex())

    with open("DES/ciphertext.txt", "wb") as file:
        file.write(ciphertext)

    # Decryption
    with open("DES/ciphertext.txt", "rb") as file:
        ciphertext = file.read()
    
    with open("DES/key.txt", "rb") as file:
        key = file.read()

    print("Ciphertext:", ciphertext)
    print("Ciphertext (hex):", ciphertext.hex())
    print("Key:", key)
    print("Key (hex):", key.hex())

    decrypted_plaintext = DES.DES_decrypt(ciphertext, key)
    print("Decrypted Plaintext:", decrypted_plaintext)
    print("Decrypted Plaintext (hex):", decrypted_plaintext.hex())

    with open("DES/decrypted_plaintext.txt", "wb") as file:
        file.write(decrypted_plaintext)