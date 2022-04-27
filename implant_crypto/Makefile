CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

.PHONY: all check_filename_hash.exe asymmetric_crypto.exe clean

check_filename_hash.exe:
	$(CXX) check_filename_hash.cpp  -lCrypt32 -lbcrypt -lshlwapi -static -o bin/check_filename_hash.exe
	
asymmetric_crypto.exe:
	$(CXX) asymmetric_crypto.cpp -lcrypt32 -lbcrypt -static -o bin/asymmetric_crypto.exe