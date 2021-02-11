import re
from capstone import *
from keystone import *

class Arch:
    def __init__(self):
        self.cs = Cs(*self._cs)
        self.cs.detail = True
        self.ks = Ks(*self._ks)

    def asm(self, asm, addr=0, att_syntax=False):
        if not asm:
            return ''
        # asm start label for use with relative offsets
        asm = '_PKST_:;' + asm

        saved = self.ks.syntax
        if att_syntax:
            self.ks.syntax = KS_OPT_SYNTAX_ATT
        tmp, _ = self.ks.asm(asm, addr=addr)
        self.ks.syntax = saved
        return ''.join(map(chr, tmp))

    def dis(self, raw, addr=0):
        return list(self.cs.disasm(str(raw), addr))

    def jmp(self, dst):
        raise NotImplementedError

    def call(self, dst):
        raise NotImplementedError

    def ret(self):
        raise NotImplementedError

    def nop(self):
        raise NotImplementedError

class x86(Arch):
    _cs = CS_ARCH_X86, CS_MODE_32
    _ks = KS_ARCH_X86, KS_MODE_32

    def call(self, dst):return 'call %s;' % hex(dst)
    def jmp(self, dst):  return 'jmp %s;' % hex(dst)

    def ret(self): return 'ret;'
    def nop(self): return 'nop;'

    # memcpy should be pc-relative
    # dst and src are offsets from the _PKST_ label
    def memcpy(self, dst, src, size):
        return '''
        push edi
        push esi
        push ecx

        call ref
        ref: pop edi
        sub edi, ref - _PKST_
        mov esi, edi

        add edi, %s
        add esi, %s
        mov ecx, %s

        rep movsb

        pop ecx
        pop esi
        pop edi
        ''' % (hex(dst), hex(src), hex(size))

class x86_64(x86):
    _cs = CS_ARCH_X86, CS_MODE_64
    _ks = KS_ARCH_X86, KS_MODE_64

    def memcpy(self, dst, src, size):
        return '''
        push rdi
        push rsi
        push rcx

        lea rdi, [rip - _PKST_ + %s]
        lea rsi, [rip - _PKST_ + %s]
        mov rcx, %s

        rep movsb

        pop rcx
        pop rsi
        pop rdi
        ''' % (hex(dst), hex(src), hex(size))

class arm(Arch):
    _cs = CS_ARCH_ARM, CS_MODE_ARM
    _ks = KS_ARCH_ARM, KS_MODE_ARM
