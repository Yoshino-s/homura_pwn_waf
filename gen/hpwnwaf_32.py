
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
	new_main = pt.inject(hex="5589e557565381ec9000000066c745ec0600c645ee00c645ef00c745f00000000066c745e40600c645e600c645e700c745e80000ff7f66c745dc1500c645de01c645df00c745e00100000066c745d41500c645d602c645d700c745d80200000066c745cc1500c645ce03c645cf00c745d00300000066c745c41500c645c604c645c700c745c80400000066c745bc2000c645be00c645bf00c745c01000000066c745b41500c645b600c645b705c745b86600000066c745ac1500c645ae07c645af00c745b06b01000066c745a41500c645a608c645a700c745a86a01000066c7459c1500c6459e09c6459f00c745a06901000066c745941500c645960ac6459700c745986701000066c7458c1500c6458e0bc6458f00c745907800000066c745841500c645860cc6458700c745880b00000066c7857cffffff2000c6857effffff00c6857fffffff00c745800000000066c78574ffffff1500c68576ffffff00c68577ffffff0ec78578ffffff0300004066c7856cffffff2000c6856effffff00c6856fffffff00c78570ffffff0400000066c78564ffffff11008d856cffffff898568ffffffb8ac000000bb26000000b901000000ba00000000be00000000bf00000000cd80b8ac000000bb16000000b9020000008d9564ffffffcd809081c4900000005b5e5f5dc3")
	pt.hook(main_addr, new_main)
