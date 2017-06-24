# -*- coding: utf-8 -*-
#import pwnlib
from pwn import *
import re

class Mod_TopFuncRef:
        
    def __init__(self):
        self.name = "topfuncref"
        self.desc = "list top 10 functions referenced"

    def run(self, helper, filelist, args):
        helper.print_title("Listing top 10 functions referenced")
        for fname in filelist:
            with open(fname, 'rb') as f:
                elf = pwnlib.elf.ELF(fname)

                for sec in elf.sections:
                    if sec.name == '.text':
                        tops = self.top_funcs(elf, sec.header['sh_addr'], sec.header['sh_size'])

            s = "    %s\n" %(fname.ljust(60))
            helper.print_normal(s)
            for sym, n in tops:
                s = "        %s: ref %4d\n" %(sym.ljust(60), n)
                helper.print_normal(s)
            helper.print_normal("\n")


    def top_funcs(self, elf, entry, size, top=10):
        calls = {}
        start = entry
        _size = min(size, 0x1000)

        while size > 0:
            data = elf.read(start, _size)
            try:
                lines = pwnlib.asm.disasm(data, 
                                      arch=elf.arch, 
                                      vma=start).split("\n")
            except TypeError:
                return sorted(calls.items(), key=lambda x: x[1])[::-1][:top]

            start = start + len(data)
            size = size - len(data)
            for i in range(len(lines)):
                s = re.sub(' +',' ', lines[i])
                if "call" in s:
                    try:
                        addr = int(s.split(" ")[-1], 16)
                        sym = hex(addr)
                        for _sym in elf.symbols:
                            if elf.symbols[_sym] == addr:
                                sym = _sym
                                break

                        if sym in calls:
                            calls[sym] = calls[sym] + 1
                        else:
                            calls[sym] = 1
                    except ValueError:
                        pass            

        return sorted(calls.items(), key=lambda x: x[1])[::-1][:top]

