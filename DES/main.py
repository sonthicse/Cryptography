import DES

if __name__ == "__main__":
    with open("DES/plaintext.txt", "rb") as file:
        plaintext = file.read()
        
    with open("DES/key.txt", "rb") as file:
        key = file.read()

    print("Plaintext:", plaintext)
    print("Plaintext (bin):", bin(int.from_bytes(plaintext, byteorder='big')))
    print("Plaintext (hex):", plaintext.hex())
    print("Key:", key)
    print("Key (bin):", bin(int.from_bytes(key, byteorder='big')))
    print("Key (hex):", key.hex())

    ciphertext = DES.DES_encrypt(plaintext, key)
    print("Ciphertext:", ciphertext)
    print("Ciphertext (bin):", bin(int.from_bytes(ciphertext, byteorder='big')))
    print("Ciphertext (hex):", ciphertext.hex())

    with open("DES/ciphertext.txt", "wb") as file:
        file.write(ciphertext)