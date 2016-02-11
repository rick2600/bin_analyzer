# -*- coding: utf-8 -*-

import os
import sys

from elftools.elf.elffile import *
from elftools.common.exceptions import ELFError

import modules
from helper import Helper


class BinAnalyzer:

    def __init__(self, args):
        self.args = args
        self.filelist = []
        self.mod_list = modules.__all__
        self.mods_choice = None
        args.no_color
        self.helper = Helper(not args.no_color)

        if args.mods != None:
                self.mods_choice = args.mods.split(',')

        if args.list:
            self.helper.print_title("Modules availables")
            for m in self.mod_list:
                mod = m()
                s = "    %s - %s\n" %(mod.name.ljust(20), mod.desc)
                self.helper.print_normal(s)

            sys.exit(0)        

    def isELF(self, filename):
        is_valid = True
        try:
            with open(filename, "rb") as f:
                try:
                    elffile = ELFFile(f)
                    text = elffile["e_machine"]
                except ELFError, e:
                    is_valid = False
                    text = "NOT ELF"
        except IOError, e:
            is_valid = False
            text = "IO ERROR"

        return is_valid, text

    def create_list_of_binaries(self):
        self.helper.print_title("Creating list of binaries")

        for (folder, _, files) in os.walk(self.args.dir):
            for f in files:
                path = os.path.abspath(os.path.join(folder, f))
                iself, text = self.isELF(path)
                if self.args.verbose > 0:
                    self.helper.print_normal("    %s|" %(path.ljust(60)))

                if iself:
                    self.filelist.append(path)
                    if self.args.verbose > 0:
                        self.helper.print_good(text)
                        self.helper.print_normal("\n")
                else:
                    if self.args.verbose > 0:
                        self.helper.print_bad(text)
                        self.helper.print_normal("\n")

        self.helper.print_normal("\n    Found %d binaries\n\n" %(len(self.filelist)))
   
    def create_out_dir(self):
        out_dir = os.path.abspath(self.args.out_dir)
        if not os.path.exists(out_dir):
            os.mkdir(out_dir)
        else:
            self.helper.print_warning("%s exists, using previous results" %(out_dir))
            self.helper.print_normal("\n")

    def pre_scan(self):
        self.create_list_of_binaries()
        self.create_out_dir()
        temp_list = list(self.mod_list)
        if self.mods_choice != None:
            if self.args.exclude:
                for m in temp_list:
                    mod = m()
                    if mod.name in self.mods_choice:
                        self.mod_list.remove(m)
                    del mod
            else:
                for m in temp_list:
                    mod = m()
                    if mod.name not in self.mods_choice:
                        self.mod_list.remove(m)
                    del mod
        else:
            self.mod_list = []
            self.helper.print_warning("select modules to run")
            self.helper.print_normal("\n")

    def scan(self):
        for m in self.mod_list:
            mod = m()
            mod.run(self.helper, self.filelist, self.args)
            print
        
