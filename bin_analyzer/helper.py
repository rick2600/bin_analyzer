# -*- coding: utf-8 -*-

class Helper:

    def __init__(self, color=True):
        self.color = color

        self.HEADER = '\033[95m'
        self.OKBLUE = '\033[94m'
        self.OKGREEN = '\033[92m'
        self.WARNING = '\033[93m'
        self.FAIL = '\033[91m'
        self.ENDC = '\033[0m'
        self.BOLD = '\033[1m'
        self.UNDERLINE = '\033[4m'

    def print_title(self, msg):
        if self.color:
            print self.OKBLUE + "[*] " + msg + self.ENDC
        else:
            print "[*] %s" %(msg)

    def print_normal(self, msg):
        print msg,

    def print_good(self, msg):
        if self.color:
            print self.OKGREEN + msg + self.ENDC,
        else:
            print msg,

    def print_warning(self, msg):
        if self.color:
            print self.WARNING + msg + self.ENDC,
        else:
            print msg,

    def print_bad(self, msg):
        if self.color:
            print self.FAIL + msg + self.ENDC,
        else:
            print msg,
