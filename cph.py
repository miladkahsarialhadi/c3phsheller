#!/usr/bin/env python3

# Cephalexin Shellcoder is a script for extracting shellcode from a binary.
# Written by Milad Kahsari Alhadi

import subprocess
import sys
import os


def Header():
	print("\n")
	print("=============================================================")
	print("\n\033[93m\033[1mCephalexin Shellcoder extracts shellcode (machine code).\033[0m")
	print("\033[93m\033[1mScript is written by Milad Kahsari Alhadi.\033[0m\n")
	print("\t\033[90m\033[1mCurrent Version: v1.2.1\033[0m\n")
	print("=============================================================")

def HelpMenu():
	print("\n")
	print("\033[92m\033[1m\tUsage: ./cph.py [Arguments] [BinaryFile]\033[0m\n")
	print("\t\033[93m\033[1mArguments\t\t\tDescription\033[0m\n")
	print("\t\033[90m\033[1m-h\t\t\t\tShows help menu\033[0m")
	print("\t\033[90m\033[1m-a\t\t\t\tExtracts shellcode from an arm binary\033[0m")
	print("\t\033[90m\033[1m-x\t\t\t\tExtracts shellcode from an intel binary\033[0m")
	print("\n")
	
def ObjDumpOutput(_arg_name):
	print("\n\033[96m\033[1mObjdump Output:\033[0m")
	output = os.popen("objdump -d -M intel " + str(_arg_name)).read()
	for line in output.split('\n'):
		if ((line.find(" 00 ") > 0)):
			print("\t\033[91m\033[1m {}\033[0m".format(line))
		elif ((line.find(" 80 ") > 0)):
			print("\t\033[92m\033[1m {}\033[0m".format(line))
		else:
			print('\t', line)

def StringFind(_arg_name):
	string = ''.join(str(e) for e in _arg_name)

	print(string.replace(r'\x00','\x1b[91m\\x00\x1b[0m') \
	.replace(r'\xcd\x80','\x1b[92m\\xcd\\x80\x1b[0m'))
    
    
def ScanStringSysCalls(_arg_string):
	totalSysCalls = 0
	print("\033[92m\033[1mSystem Calls Detected:\033[0m\n")

	for pos, check in enumerate(_arg_string):
		if check == '\\xcd':
			totalSysCalls += 1

	print("\n\t\033[95m\033[1mTotal system calls in the shellcode: {}\033[0m\n".format(totalSysCalls))


def ScanStringNullByte(_arg_string):
	totalNullByte = 0
	print("\033[91m\033[1mNull Bytes Detected:\033[0m\n")

	for pos, check in enumerate(_arg_string):
		if check == '\\x00':
			totalNullByte += 1

	print("\n\t\033[95m\033[1mTotal null bytes in the shellcode: {}\033[0m\n".format(totalNullByte))



def ExtractShellcodeArm(_arg_name):
	ObjDumpOutput(_arg_name)
	print("\033[101m\033[1mExtracted Shellcode:\033[0m\n")
	
	proc = subprocess.Popen(['objdump','-d', '--endian=big',_arg_name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	
	while True:
		line = proc.stdout.readline()
		if line != b'':
			array = line.decode().rstrip().split(':')
			if len(array) > 1:
				if array[1]:
					array2 =  array[1].split(' ')
					array2 = array2[0].lstrip().rstrip()
					if array2:
						sc_part = '\t"'
						sc_part += '\\x'
						sc_part += '\\x'.join(a+b for a,b in zip(array2[::2], array2[1::2]))
						sc_part += '"'
						print(sc_part)
		else:
		   break
	
	print("\n")
	ScanStringNullByte(sc_part)
	
def ExtractShellcodeIntel(_arg_name):
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
        print("\033[101m\033[1mExtracted Shellcode:\033[0m\n")
        print("\t", end="")
        StringFind(result)
        print("\n")

        ScanStringNullByte(result)
        ScanStringSysCalls(result)
        

def EntryPoint():
	if len(sys.argv) != 3:
		HelpMenu()
		
	elif sys.argv[1] == "-h" or sys.argv[1] == "--help":
		HelpMenu()
		
	elif sys.argv[1] == "-a" or sys.argv[1] == "--arm":
		ExtractShellcodeArm(sys.argv[2])
		
	elif sys.argv[1] == "-i" or sys.argv[1] == "--intel":
		ExtractShellcodeIntel(sys.argv[2])
		
	else:
		HelpMenu()


if __name__ == "__main__":
	Header()
	EntryPoint()  
