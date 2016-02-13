# -*- coding: utf-8 -*-
import os
import subprocess
import re
import hashlib

STRINGS_PATH = "/usr/bin/strings"

class Mod_Strings:
    
    def __init__(self):
        self.name = "strings"
        self.desc = "look for interesting strings"

    def run(self, helper, filelist, args):
        helper.print_title("Looking for interesting strings")
        for fname in filelist:
            printed = False
            
            fout = self.run_strings(fname, args)
            with open(fout, 'rb') as f:
                lines = f.readlines()
                for line in lines:
                    if re.match("http?://", line, re.I):
                        if not printed:
                            helper.print_normal("    %s\n" %(fname))
                            printed = True
                        helper.print_normal("        %s" %(line))
                    if re.match("ftp://", line, re.I):
                        if not printed:
                            helper.print_normal("    %s\n" %(fname))
                            printed = True
                        helper.print_normal("        %s" %(line))
                    if re.match("pwd", line, re.I):
                        if not printed:
                            helper.print_normal("    %s\n" %(fname))
                            printed = True
                        helper.print_normal("        %s" %(line))
                    if re.match("pass", line, re.I):
                        if not printed:
                            helper.print_normal("    %s\n" %(fname))
                            printed = True
                        helper.print_normal("        %s" %(line))
                    if re.match("user", line, re.I):
                        if not printed:
                            helper.print_normal("    %s\n" %(fname))
                            printed = True
                        helper.print_normal("        %s" %(line))
                        
                if printed:
                    helper.print_normal("\n")


    def run_strings(self, fname, args):
        #dir_path = os.path.abspath(args.dir) + "/"
        #_fout = fname.replace(dir_path, "").replace("/", "_") + ".txt"
        #fout = os.path.join(args.out_dir, _fout)
        m = hashlib.sha1()
        m.update(fname)
        fout = os.path.join("/tmp", "bin_" + m.hexdigest() + ".txt")
        if not os.path.exists(fout):
            outfd = open(fout, 'w')
            subprocess.call([STRINGS_PATH, "-a", fname], stdout=outfd)
            subprocess.call([STRINGS_PATH, "-a", "-e", "l", fname], stdout=outfd)
            outfd.close()
        return fout

