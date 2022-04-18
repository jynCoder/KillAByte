CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

check_filename_hash.exe:
	$(CXX) check_filename_hash.cpp  -lCrypt32 -lbcrypt -static -o check_filename_hash.exe 