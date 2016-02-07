# -*- coding: utf-8 -*-

from elftools.elf.elffile import *


class Mod_CheckSec:
        
    def __init__(self):
        self.name = "dangerous"
        self.desc = "find use of dangerous functions"

    def run(self, helper, filelist, args):
        helper.print_title("Finding use of dangerous functions")
        for fname in filelist:
            funcs = []
            with open(fname, "rb") as f:
                elffile = ELFFile(f)
                all_funcs = self.get_func_used(elffile)

                # This shouldn't be a long list
                if "strcpy" in all_funcs: funcs.append("strcpy")
                if "strcat" in all_funcs: funcs.append("strcat")
                if "memcpy" in all_funcs: funcs.append("memcpy")
                if "system" in all_funcs: funcs.append("system")
                if "gets" in all_funcs: funcs.append("gets")
                if "scanf" in all_funcs: funcs.append("scanf")
                if "sprintf" in all_funcs: funcs.append("sprintf")




                funcs_str = ", ".join(funcs)
                helper.print_normal("    %s|" %(fname.ljust(60)))
                helper.print_bad("%s" %(funcs_str))
                helper.print_normal("\n")



    def get_func_used(self, elffile):
        jmp_slot = []
        for section in elffile.iter_sections():
            if not isinstance(section, RelocationSection):
                continue

            symtable = elffile.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if isinstance(symtable, NullSection):
                    continue
                symbol = symtable.get_symbol(rel['r_info_sym'])
                if rel['r_info_type'] == 7:
                    jmp_slot.append(symbol.name)

        return jmp_slot
