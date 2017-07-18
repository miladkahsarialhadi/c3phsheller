#!/usr/bin/env python3

# Cephalexin Shellcoder is a script for extracting shellcode from a binary.
# Written by Milad Kahsari Alhadi


import sys
import os
import re

def Header():
        print("\n")
        print("=============================================================")
        print("\n\033[93m\033[1mCephalexin Shellcoder extracts shellcode (machine code).\033[0m")
        print("\033[93m\033[1mScript is written by Milad Kahsari Alhadi.\033[0m\n")
        print("=============================================================")

def ObjDumpOutput(_arg_name):
        print("\n\033[96m\033[1mObjdump Output:\033[0m")
        output = os.popen("objdump -d -M intel " + str(_arg_name)).read()
        for line in output.split('\n'):
                print('\t', line)

def ExtractShellcode(_arg_name):
        g1 = "grep '[0-9a-f]:'"
        g2 = "grep -v 'file'"
        g3 = "cut -f2 -d:"
        g4 = "cut -f1-6 -d' '"
        g5 = "tr -s ' '"
        g6 = "sed 's/ $//g'"
        g7 = "sed 's/ //g'"
        g8 = "paste -d '' -s "
        g9 = "sed 's/^/\"/'"
        g10 = "sed 's/$/\"/g'"
        gg = "tr '\\t' ' '"

        objdump = "objdump -d " + str(_arg_name) + "|" + g1 + "|" + g2 + "|" + g3 + "|" + g4 + "|" + g5 + "|" + gg + "|" + g6 + "|" + g7 + "|" + g8 + "|" + g9 + "|" + g10
        result = os.popen(objdump).read()
        result = result.replace('"','')

        length = len(result) - 1
        result = [r'\x' + result[i:i + 2] for i in range(0, length, 2)]
	
        ObjDumpOutput(_arg_name)
        print("\033[91m\033[1mExtracted Shellcode:\033[0m\n")
        print("\t {}". format(''.join(result)))
        print("\n")


def EntryPoint():
        if len(sys.argv) != 2:
                print("\n\t\033[96mUsage: ./c3phsheller [binary]\033[0m\n\n")

        else:
                ExtractShellcode(sys.argv[1])
		

if __name__ == "__main__":
        Header()
        EntryPoint()  
