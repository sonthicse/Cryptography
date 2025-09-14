import tables
import random

def generate_random_key() -> bytes:
    key = random.randbytes(8)
    return key

def Permute(block: int, table: list, size: int) -> int:
    permuted = 0

    for i in range(len(table)):
        bit = (block >> (size - table[i])) & 1
        permuted = (permuted << 1) | bit

    return permuted

def P_box(block: int, table: list, size: int) -> int:
    permuted = Permute(block, table, size)

    return permuted

def E_box(block: int, table: list, size: int) -> int:
    expanded = Permute(block, table, size)

    return expanded

def S_box(block: int, table: list) -> int:
    output = 0

    for i in range(8):
        six_bits = (block >> (42 - 6 * i)) & 0b111111

        row = ((six_bits & 0b100000) >> 4) | (six_bits & 0b000001)
        col = (six_bits >> 1) & 0b1111

        s_value = table[i][row][col]
        output = (output << 4) | s_value

    return output

def left_circular_shift(block: int, shifts: int) -> int:
    shifted = ((block << shifts) & 0xFFFFFFF) | (block >> (28 - shifts))
    return shifted

def key_schedule(key: bytes) -> list:
    subkey = P_box(int.from_bytes(key, byteorder='big'), tables.PC_1, 64)

    left_key_half = (subkey >> 28) & 0xFFFFFFF
    right_key_half = subkey & 0xFFFFFFF

    round_keys = []

    for round in range(16):
        left_key_half = left_circular_shift(left_key_half, tables.shifts[round])
        right_key_half = left_circular_shift(right_key_half, tables.shifts[round])

        round_key = (left_key_half << 28) | right_key_half

        round_key = P_box(round_key, tables.PC_2, 56)

        round_keys.append(round_key)

    return round_keys

def mangler_function(left_half: int, right_half: int, round_key: int) -> list:
    expanded_right_half = E_box(right_half, tables.E, 32)

    xor_right_half = expanded_right_half ^ round_key

    substituted_right_half = S_box(xor_right_half, tables.S)

    permuted_right_half = P_box(substituted_right_half, tables.P, 32)

    new_right_half = left_half ^ permuted_right_half

    return [right_half, new_right_half]

def round_function(left_half: int, right_half: int, round_key: int) -> list:
    left_half, right_half = mangler_function(left_half, right_half, round_key)

    return [left_half, right_half]

def DES_encrypt(plaintext: bytes, key: bytes) -> bytes:
    padding_length = 8 - (len(plaintext) % 8)
    plaintext = plaintext + bytes([padding_length] * padding_length)

    round_keys = key_schedule(key)
    ciphertext = bytearray()

    for i in range(0, len(plaintext), 8):
        block = plaintext[i: i + 8]
        block = int.from_bytes(block, byteorder='big')

        block = P_box(block, tables.IP, 64)

        left_half = (block >> 32) & 0xFFFFFFFF
        right_half = block & 0xFFFFFFFF

        for round in range(16):
            left_half, right_half = round_function(left_half, right_half, round_keys[round])

        block = (right_half << 32) | left_half

        block = P_box(block, tables.FP, 64)

        ciphertext = ciphertext + block.to_bytes(8, byteorder='big')

    return bytes(ciphertext)

def DES_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    plaintext = bytearray()

    round_keys = key_schedule(key)
    
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i: i + 8]

        block = int.from_bytes(block, byteorder='big')

        block = P_box(block, tables.IP, 64)

        left_half = (block >> 32) & 0xFFFFFFFF
        right_half = block & 0xFFFFFFFF

        for round in range(15, -1, -1):
            left_half, right_half = round_function(left_half, right_half, round_keys[round])

        block = (right_half << 32) | left_half

        block = P_box(block, tables.FP, 64)

        plaintext = plaintext + block.to_bytes(8, byteorder='big')

    padding_length = plaintext[-1]
    plaintext = plaintext[0: len(plaintext) - padding_length]

    return bytes(plaintext)