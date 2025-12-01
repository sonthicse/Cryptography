# AES-128 ECB, nhiều block, PKCS#7 padding
# Không dùng thư viện ngoài, không định nghĩa hàm tự viết.

# 1. Bảng S-box (SubBytes)
s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# 2. Bảng nhân GF(2^8) cho 2 và 3 (MixColumns)
mul2 = [0] * 256
mul3 = [0] * 256
i = 0
while i < 256:
    x = i
    xtime = (x << 1) & 0xff
    if x & 0x80:
        xtime ^= 0x1b
    mul2[i] = xtime
    mul3[i] = xtime ^ x
    i += 1

# 3. Rcon cho key schedule AES-128
rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# ================== NHẬP DỮ LIỆU ==================
# Plaintext có thể dài tùy ý
plaintext_str = "The quick brown fox jumps over the lazy dog."
# Khóa 16 byte (AES-128)
key_str       = "abcdefghijklmnop"

# Chuyển plaintext sang mảng byte
plaintext_bytes = []
i = 0
while i < len(plaintext_str):
    plaintext_bytes.append(ord(plaintext_str[i]))
    i += 1

# PKCS#7 padding
length = len(plaintext_bytes)
remainder = length % 16
if remainder == 0:
    pad_len = 16
else:
    pad_len = 16 - remainder

i = 0
while i < pad_len:
    plaintext_bytes.append(pad_len)
    i += 1

# Chuyển key sang mảng byte 16 phần tử
key = [0] * 16
i = 0
while i < 16:
    key[i] = ord(key_str[i])
    i += 1

# ================== KEY SCHEDULE (mở rộng khóa) ==================
round_keys = [0] * 176   # 11 * 16
i = 0
while i < 16:
    round_keys[i] = key[i]
    i += 1

generated = 16
rcon_iter = 0
temp = [0] * 4

while generated < 176:
    i = 0
    while i < 4:
        temp[i] = round_keys[generated - 4 + i]
        i += 1

    if generated % 16 == 0:
        # RotWord
        t = temp[0]
        temp[0] = temp[1]
        temp[1] = temp[2]
        temp[2] = temp[3]
        temp[3] = t
        # SubWord
        temp[0] = s_box[temp[0]]
        temp[1] = s_box[temp[1]]
        temp[2] = s_box[temp[2]]
        temp[3] = s_box[temp[3]]
        # XOR Rcon
        temp[0] ^= rcon[rcon_iter]
        rcon_iter += 1

    i = 0
    while i < 4:
        round_keys[generated] = round_keys[generated - 16] ^ temp[i]
        generated += 1
        i += 1

# ================== MÃ HÓA NHIỀU BLOCK (ECB) ==================
total_len = len(plaintext_bytes)
num_blocks = total_len // 16

cipher_bytes = [0] * total_len

block = 0
while block < num_blocks:
    # Khởi tạo state cho block này
    state = [0] * 16
    i = 0
    while i < 16:
        state[i] = plaintext_bytes[block * 16 + i]
        i += 1
    # Round 0: AddRoundKey
    i = 0
    while i < 16:
        state[i] ^= round_keys[i]
        i += 1
    print(state)
    # Round 1..9
    round_num = 1
    while round_num <= 9:
        # SubBytes
        i = 0
        while i < 16:
            state[i] = s_box[state[i]]
            i += 1

        # ShiftRows
        t1 = state[1]
        t2 = state[5]
        t3 = state[9]
        t4 = state[13]
        state[1]  = t2
        state[5]  = t3
        state[9]  = t4
        state[13] = t1

        t1 = state[2]
        t2 = state[6]
        t3 = state[10]
        t4 = state[14]
        state[2]  = t3
        state[6]  = t4
        state[10] = t1
        state[14] = t2

        t1 = state[3]
        t2 = state[7]
        t3 = state[11]
        t4 = state[15]
        state[3]  = t4
        state[7]  = t1
        state[11] = t2
        state[15] = t3

        # MixColumns
        col = 0
        while col < 4:
            i0 = 4 * col + 0
            i1 = 4 * col + 1
            i2 = 4 * col + 2
            i3 = 4 * col + 3

            a0 = state[i0]
            a1 = state[i1]
            a2 = state[i2]
            a3 = state[i3]

            r0 = mul2[a0] ^ mul3[a1] ^ a2 ^ a3
            r1 = a0 ^ mul2[a1] ^ mul3[a2] ^ a3
            r2 = a0 ^ a1 ^ mul2[a2] ^ mul3[a3]
            r3 = mul3[a0] ^ a1 ^ a2 ^ mul2[a3]

            state[i0] = r0
            state[i1] = r1
            state[i2] = r2
            state[i3] = r3

            col += 1

        # AddRoundKey round hiện tại
        offset = round_num * 16
        i = 0
        while i < 16:
            state[i] ^= round_keys[offset + i]
            i += 1

        round_num += 1

    # Round 10 (cuối): SubBytes + ShiftRows + AddRoundKey (không MixColumns)
    i = 0
    while i < 16:
        state[i] = s_box[state[i]]
        i += 1

    t1 = state[1]
    t2 = state[5]
    t3 = state[9]
    t4 = state[13]
    state[1]  = t2
    state[5]  = t3
    state[9]  = t4
    state[13] = t1

    t1 = state[2]
    t2 = state[6]
    t3 = state[10]
    t4 = state[14]
    state[2]  = t3
    state[6]  = t4
    state[10] = t1
    state[14] = t2

    t1 = state[3]
    t2 = state[7]
    t3 = state[11]
    t4 = state[15]
    state[3]  = t4
    state[7]  = t1
    state[11] = t2
    state[15] = t3

    offset = 10 * 16
    i = 0
    while i < 16:
        state[i] ^= round_keys[offset + i]
        i += 1

    # Ghi cipher block này ra cipher_bytes
    i = 0
    while i < 16:
        cipher_bytes[block * 16 + i] = state[i]
        i += 1

    block += 1

# ================== IN KẾT QUẢ TOÀN BỘ (HEX) ==================
cipher_hex = ""
i = 0
while i < len(cipher_bytes):
    b = cipher_bytes[i]
    if b < 0:
        b += 256
    cipher_hex += format(b, "02x")
    i += 1

print("Cipher (hex):", cipher_hex)
