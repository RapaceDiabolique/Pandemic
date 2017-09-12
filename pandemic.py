#!/usr/bin/env python3

#
# Made by the Rapace Diabolique
#

import os
import sys
import argparse
import signal

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

    " Look for ST_UID bit "
    if filemode & S_ISUID != 0:
        print_interesting_file(path, "ST_UID")

def walk_path(rootdir, exclude_dirs):
    if not os.path.isdir(rootdir):
        print("[-] The given root path is not valid", file=sys.stderr)
        sys.exit(1)
    for root, subdirs, files in os.walk(rootdir):
        subdirs[:] = [d for d in subdirs if os.path.join(root, d) not in exclude_dirs]
        for filename in files:
            try:
                path = os.path.join(root, filename)
                analyze_file(path)
            except (FileNotFoundError, PermissionError):
                pass

def main():
    global found

    " Argument parsing "
    parser = argparse.ArgumentParser(description = "Walks directory, looking for interesting files")
    parser.add_argument("directory", metavar="dir", help="The directory to walk through")
    parser.add_argument("-e", "--exclude", metavar="exclude_dir", default=["/dev", "/proc"], nargs="*", help="The directory to exclude (absolute path)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Make output more verbose")
    parser.add_argument("-V", "--version", action="store_true", help="Print version number")
    args = parser.parse_args()

    print("[+] Pandemic {}.{}.{}".format(pandemic_major, pandemic_minor, pandemic_bug))
    print("[+] Made by the Rapace Diabolique")
    print("")
    print("Searching from '{}'".format(args.directory))
    print("")

    signal.signal(signal.SIGINT, signal_handler)

    rootdir = os.path.abspath(sys.argv[1])
    walk_path(rootdir, args.exclude)

    if found:
        print("")
        print("[+] Analyze complete")
    else:
        print("[-] Nothing was found")

def signal_handler(signal, frame):
        print("[-] Search cancelled")
        sys.exit(0)

if __name__ == '__main__':
    main()
