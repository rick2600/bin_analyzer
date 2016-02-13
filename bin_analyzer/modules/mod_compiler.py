# -*- coding: utf-8 -*-
from elftools.elf.elffile import *

class Mod_Compiler:

    def __init__(self):
        self.name = "compiler"
        self.desc = "try to identify compiler information from the elf sections"

    def run(self, helper, filelist, args):
        helper.print_title("Identifying compiler information")
        for fname in filelist:
            with open(fname, 'rb') as f:
                elffile = ELFFile(f)
                s = "    %s| %s\n" %(fname.ljust(60), self.get_comment(elffile))
                helper.print_normal(s)

    def get_comment(self, elffile):
        for section in elffile.iter_sections():
            if section.name.startswith('.comment'):
                return section.data()
