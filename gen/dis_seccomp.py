#!/usr/bin/env python3
from pwnlib.elf.elf import ELF, Function
from pwnlib.asm import disasm
import binascii
import sys

elf = ELF(sys.argv[1])
secomp: Function = elf.functions["seccomp"]
hex = binascii.hexlify(elf.read(secomp.address, secomp.size)).decode()
code = f"""
#coding:utf-8
from pwnlib.elf.elf import ELF

def replace_waf(pt):
	func = ELF(pt.binary.path).functions
	if func.get("main"):
		main_addr = func.get("main").address
	elif func.get("_main"):
		main_addr = func.get("_main").address
	else:
		pt.warn("Cannot automatically get main address")
		main_addr = 0x1199 #main函数入口地址
	assert(main_addr)
	new_main = pt.inject(hex="{hex}")
	pt.hook(main_addr, new_main)
"""
print(code)
sys.stderr.write(secomp.disasm())