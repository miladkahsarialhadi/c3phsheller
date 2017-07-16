#!/usr/bin/env python3

# C3phsheller is a script for extracting shellcode from a binary.
# Written by Milad Kahsari Alhadi


import sys
import os

def extract(name):
        g1 = "grep '[0-9a-f]:'"
        g2 = "grep -v 'file'"
        g3 = "cut -f2 -d:"
        g4 = "cut -f1-6 -d' '"
        g5 = "tr -s ' '"
        g6 = "sed 's/ $//g'"
        g7 = "sed 's/ /\\x/g'"
        g8 = "paste -d '' -s "
        g9 = "sed 's/^/\"/'"
        g10 = "sed 's/$/\"/g'"
        gg = "tr '\\t' ' '"

        cmd1 = "objdump -d "
        cmd2 = str(name) + "|" + g1 + "|" + g2 + "|" + g3 + "|" + g4 + "|" + g5 + "|" + gg + "|" + g6 + "|" + g7 + "|" + g8 + "|" + g9 + "|" + g10

        cmd3 = str(cmd1) + str(cmd2)
        res = os.popen(cmd3).read()
        print(res)

def main():

        if len(sys.argv) != 2:
                print("Usage: ./c3phsheller shellcode")

        else:
                extract(sys.argv[1])

if __name__ == "__main__":
        main()
