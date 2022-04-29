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
	$(CXX) loot.cpp sqlite3.o -lpthread -ldl -lCrypt32 -static -o bin/loot.exe