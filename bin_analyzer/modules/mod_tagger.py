# -*- coding: utf-8 -*-
from elftools.elf.elffile import *

class Mod_Tagger:
        
    def __init__(self):
        self.name = "tagger"
        self.desc = "try to identify the purpose of binary and tag it"

    def run(self, helper, filelist, args):
        helper.print_title("Tagging binaries")
        for fname in filelist:
            with open(fname, 'rb') as f:
                elffile = ELFFile(f)
                tags = self.get_tags(elffile)
                s = "    %s| %s\n" %(fname.ljust(60), ', '.join(tags))
                helper.print_normal(s)

    def get_tags(self, elffile):
        tags = []
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

        # file
        for tag in ["fopen"]:
            if tag in jmp_slot:
                tags.append("file")
                break

        # heap
        for tag in ["malloc", "calloc", "realloc"]:
            if tag in jmp_slot:
                tags.append("heap")
                break

        # networking server
        for tag in ["accept", "listen"]:
            if tag in jmp_slot:
                tags.append("net server")
                break

        # networking
        for tag in ["socket", "getaddrinfo", "recv", "recvmsg", "recvfrom", "gethostbyname"]:
            if tag in jmp_slot:
                tags.append("net")
                break

        # networking client
        for tag in ["connect"]:
            if tag in jmp_slot:
                tags.append("net client")
                break

        # pipe
        for tag in ["pipe"]:
            if tag in jmp_slot:
                tags.append("pipe")
                break

        # thread
        for tag in ["pthread_create"]:
            if tag in jmp_slot:
                tags.append("thread")
                break

        for tag in ["system", "popen","execl", "execlp", 
                    "execle","execv","execvp","execvp", "execve"]:
            if tag in jmp_slot:
                tags.append("exec")
                break

        for tag in ["srand", "rand"]:
            if tag in jmp_slot:
                tags.append("random")
                break 

        return tags

