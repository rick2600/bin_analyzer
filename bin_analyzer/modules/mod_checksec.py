# -*- coding: utf-8 -*-

from elftools.elf.elffile import *


class Mod_CheckSec:
        
    def __init__(self):
        self.name = "checksec"
        self.desc = "analyze security mitigations"

    def run(self, helper, filelist, args):
        unique_deps = []
        helper.print_title("Checking security mitigations")
        for fname in filelist:
            deps = []
            with open(fname, "rb") as f:
                elffile = ELFFile(f)
                nx = self.nx(elffile)
                pie = self.pie(elffile)
                relro = self.relro(elffile)
                funcs = self.get_func_used(elffile)
                canary = self.canary(funcs)
                fortify = self.fortify(funcs)


            helper.print_normal("    %s|" %(fname.ljust(60)))
            if nx:
                helper.print_good("nx on ")
            else:    
                helper.print_bad ("nx off")
            helper.print_normal("|")

            if canary:
                helper.print_good("canary on ")
            else:    
                helper.print_bad ("canary off")
            helper.print_normal("|")


            if fortify:
                helper.print_good("fortify on ")
            else:    
                helper.print_bad ("fortify off")
            helper.print_normal("|")

            if pie == 0:
                helper.print_bad ("pie off")
            elif pie == 1:
                helper.print_good("pie on ")
            else:
                helper.print_normal("  dso  ")
            helper.print_normal("|")


            if relro == 0:
                helper.print_bad("no relro")
            elif relro == 1:
                helper.print_warning("partial relro")
            else:
                helper.print_good("full relro")
            helper.print_normal("\n")


    def nx(self, elffile):
        status = True
        for segment in elffile.iter_segments():
            if segment["p_type"] == "PT_GNU_STACK":
                if (segment["p_flags"] & 1):
                    status = False
        return status

    def relro(self, elffile):
        status = 0
        for segment in elffile.iter_segments():
            if segment["p_type"] == "PT_GNU_RELRO":
                status = 1
                for section in elffile.iter_sections():
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag['d_tag'] == 'DT_BIND_NOW':
                                status = 2
                                break
        return status

    def fortify(self, funcs):
        for func in funcs:
            if func.endswith("_chk"):
                return True
        return False

    def pie(self, elffile):
        #print vars(elffile)
        if elffile['e_type'] == 'ET_EXEC':
            return 0
        if elffile['e_type'] == 'ET_DYN':
            for section in elffile.iter_sections():
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag['d_tag'] == 'DT_DEBUG':
                            return 1
                        #if tag['d_tag'] == 'DT_NEEDED':
            return 2

    def canary(self, funcs):
        if "__stack_chk_fail" in funcs:
            return True
        else:
            return False

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
