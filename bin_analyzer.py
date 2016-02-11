#! /usr/bin/env python
# -*- coding: utf-8 -*-

from bin_analyzer.core import BinAnalyzer
import argparse


def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument('-l', '--list', 
                        action='store_true', help='list modules')

    parser.add_argument('-d', '--dir', 
                        type=str, help='directory of binaries')

    parser.add_argument('-v', '--verbose', 
                        type=int, 
                        default=0,
                        help='control verbosity (1-3)')

    parser.add_argument('-m', '--mods', 
                        type=str, 
                        help='run only this list of modules (sep by comma) \
                        <default: all>')

    parser.add_argument('-x', '--exclude', 
                        action='store_true', 
                        help='do not run this list of modules (used with -m)')

    parser.add_argument('--no-color', 
                        action='store_true', 
                        help='disable coloring')

    parser.add_argument('-o', '--out-dir', 
                        type=str, 
                        help='directory to save output')

    parser.set_defaults(no_color=False)

    return parser.parse_args()

def validate_args(args):
    valid = True
    if args.list == False:
        if args.dir == None:
            print "-d required"
            valid = False
        if args.out_dir == None:
            print "-o required"
            valid = False

    return valid


def main():
    args = parse_args()
    if validate_args(args):
        bin_analyzer = BinAnalyzer(args)
        bin_analyzer.pre_scan()
        bin_analyzer.scan()

if __name__ == "__main__":
    main()