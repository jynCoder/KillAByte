CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

.PHONY: all readfile.exe clean

readfile:
	$(CC) fileio.c filesize.c symbolic.c -c
	$(CXX) readfile.cpp  -lwinhttp -static -o bin/readfile.exe

