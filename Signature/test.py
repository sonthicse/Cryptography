from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import number

# 1. Tạo (hoặc lần đầu khởi tạo) cặp khóa
key = RSA.generate(2048)

with open("priv.pem", "wb") as f:
    f.write(key.export_key())

with open("pub.pem", "wb") as f:
    f.write(key.publickey().export_key())

# 2. Đọc ảnh
with open("avatar.jpeg", "rb") as f:
    data = f.read()

# 3. Hash SHA-256
h_bytes = SHA256.new(data).digest()      # 32 bytes
h_int = int.from_bytes(h_bytes, "big")   # chuyển sang số nguyên

# 4. Ký theo textbook RSA: s = h^d mod n (KHÔNG padding)
n = key.n
d = key.d    # có sẵn trong key, không cần tự tính lại

sig_int = pow(h_int, d, n)
sig_bytes = number.long_to_bytes(sig_int)

# 5. Lưu chữ ký ra file riêng
with open("avatar.jpeg.sig", "wb") as f:
    f.write(sig_bytes)

print("Đã ký xong (textbook RSA, không padding).")
