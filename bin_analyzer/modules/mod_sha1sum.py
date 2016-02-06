# -*- coding: utf-8 -*-
import hashlib

class Mod_Sha1Sum:
    
    def __init__(self):
        self.name = "sha1sum"
        self.desc = "compute and check SHA1 message digest"

    def run(self, helper, filelist, args):
        helper.print_title("Computing SHA1 message digest")
        for fname in filelist:
            s = "    %s| %s\n" %(fname.ljust(60), self.sha1sum(fname))
            if args.verbose >= 1:
                helper.print_normal(s)


    def sha1sum(self, path):
        try:
            with open(path, 'rb') as f:
                m = hashlib.sha1()
                while True:
                    data = f.read(8192)
                    if not data:
                        break
                    m.update(data)
                return m.hexdigest()
        except IOError, e :
            return "ERROR"