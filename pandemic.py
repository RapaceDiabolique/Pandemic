#!/usr/bin/env python3

#
# Made by the Rapace Diabolique
#

import os
import sys

from stat import *

pandemic_major = 0
pandemic_minor = 0
pandemic_bug = 1

found = False

def print_usage():
    print("Usage: {} <dir_to_scan>".format(sys.argv[0]))

def print_interesting_file(path, reason):
    global found

    print("[+] {:30}{}".format(reason, path))
    found = True

def analyze_file(path):
    filestat = os.stat(path)
    filemode = filestat.st_mode
    if filemode & S_ISUID != 0:
        print_interesting_file(path, "SETUID")

def walk_path(rootdir):
    rootdir = os.path.abspath(rootdir)
    if not os.path.isdir(rootdir):
        print("[-] The given root path is not valid", file=sys.stderr)
        sys.exit(1)
    for root, subdirs, files in os.walk(rootdir):
        for filename in files:
            try:
                path = os.path.join(root, filename)
                analyze_file(path)
            except (FileNotFoundError, PermissionError):
                pass

def main():
    global found

    if len(sys.argv) != 2:
        print_usage()
        sys.exit(1)
    print("[+] Pandemic {}.{}.{}".format(pandemic_major, pandemic_minor, pandemic_bug))
    print("[+] Made by the Rapace Diabolique")
    print("")
    print("Searching from '{}'".format(sys.argv[1]))
    print("")

    walk_path(sys.argv[1])

    if found:
        print("")
        print("[+] Analyze complete")
    else:
        print("[-] Nothing was found")

if __name__ == '__main__':
    main()
