
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
	new_main = pt.inject(hex="554889e54883ec0866c745f00600c645f200c645f300c745f40000000066c745e80600c645ea00c645eb00c745ec0000ff7f66c745e01500c645e201c645e300c745e43b00000066c745d81500c645da02c645db00c745dc3800000066c745d01500c645d203c645d300c745d43200000066c745c81500c645ca04c645cb00c745cc3100000066c745c01500c645c205c645c300c745c42a00000066c745b81500c645ba06c645bb00c745bc2900000066c745b01500c645b200c645b307c745b4ffffffff66c745a83500c645aa00c645ab01c745ac0000004066c745a02000c645a200c645a300c745a40000000066c745981500c6459a00c6459b0ac7459c3e0000c066c745902000c6459200c6459300c745940400000066c745800d00488d459048894588b89d000000bf26000000be01000000ba0000000041ba0000000041b8000000000f05b89d000000bf16000000be02000000488d55800f0590c9c3")
	pt.hook(main_addr, new_main)

