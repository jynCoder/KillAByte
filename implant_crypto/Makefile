CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

.PHONY: all check_filename_hash.exe clean

check_filename_hash.exe:
	$(CXX) check_filename_hash.cpp  -lCrypt32 -lbcrypt -lshlwapi -static -o check_filename_hash.exe 