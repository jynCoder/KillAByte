CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

.PHONY: all loot.exe clean

loot.exe:
	$(CC) sqlite3.c -c
	$(CXX) loot.cpp http.cpp aesgcm.cpp sqlite3.o -lwinhttp -lpthread -lCrypt32 -lbcrypt -static -o bin/loot.exe