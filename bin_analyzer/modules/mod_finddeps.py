# -*- coding: utf-8 -*-

from elftools.elf.elffile import *


class Mod_FindDeps:
        
    def __init__(self):
        self.name = "finddeps"
        self.desc = "find dependencies of a binary"

    def run(self, helper, filelist, args):
        unique_deps = []
        helper.print_title("Finding dependencies")
        for fname in filelist:
            deps = []
            with open(fname, 'rb') as f:
                elffile = ELFFile(f)
                for section in elffile.iter_sections():
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag['d_tag'] == 'DT_NEEDED':
                                deps.append(tag.needed)
                                if tag.needed not in unique_deps:
                                    unique_deps.append(tag.needed)

            #if args.verbose >= 1:
            trunc = ', '.join(deps[0:3])
            if len(deps) > 3:
                trunc += '...'

            s = "    %s| %d deps found (%s)\n" %(fname.ljust(60), len(deps), trunc)
            helper.print_normal(s)

            if args.verbose >= 1:
                for dep in deps:
                    helper.print_normal("        %s\n"%(dep))
                helper.print_normal("\n")

        helper.print_normal("    Found %d unique deps\n" %(len(unique_deps)))
