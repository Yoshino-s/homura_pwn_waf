#!/usr/bin/env python3
import sys
import struct

f = sys.stdin.buffer.read()

if len(f)/8 != int(len(f)/8):
    print("Wrong file, file size must be 8n")
    exit(1)
l = len(f) // 8
s = []
for i in range(0, len(f), 8):
    a = struct.unpack("HBBI", f[i:i+8])
    s.append(f"sfi[{i//8}].code = 0x%02x;sfi[{i//8}].jt = 0x%02x;sfi[{i//8}].jf = 0x%02x;sfi[{i//8}].k = 0x%08x;\n"%(a[0],a[1],a[2], a[3]))
s.reverse()
code = f"""
struct sock_filter sfi[{l}];
{"".join(s)}
struct sock_fprog sfp = {{{l}, sfi}};
"""
print(code)
