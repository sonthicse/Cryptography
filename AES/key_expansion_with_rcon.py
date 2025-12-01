# Code cần sửa trong AES.ipynb (dòng L1-L9)
# Thêm phần tính Rcon vào key expansion

for i in range(4, 44, 1):
    if (i % 4 == 0):
        # Bước 1: RotWord - xoay byte
        rot_word = round_keys[i-1][1:] + round_keys[i-1][0:1]
        print(f"RotWord: {rot_word}")
        
        # Bước 2: SubWord - thay thế byte qua S-box
        sub_word = S_BOX(rot_word, SBOX)
        print(f"SubWord length: {len(sub_word)}")
        print(f"SubWord: {sub_word}")
        
        # Bước 3: XOR với Rcon
        # i // 4 để lấy index của Rcon (vì mỗi 4 word tạo 1 round key)
        rcon_index = i // 4
        rcon_bytes = bytes(RCON[rcon_index])
        
        # XOR sub_word với rcon
        temp = bytes([sub_word[j] ^ rcon_bytes[j] for j in range(4)])
        print(f"After XOR with Rcon[{rcon_index}]: {temp}")
        
        # Bước 4: XOR với round_keys[i-4]
        new_key = bytes([temp[j] ^ round_keys[i-4][j] for j in range(4)])
        
        round_keys.append(new_key)
    else:
        # Khi i % 4 != 0, chỉ cần XOR round_keys[i-1] với round_keys[i-4]
        new_key = bytes([round_keys[i-1][j] ^ round_keys[i-4][j] for j in range(4)])
        round_keys.append(new_key)
