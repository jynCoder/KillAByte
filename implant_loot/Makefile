CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

.PHONY: all loot.exe clean

loot.exe:
	$(CXX) loot.cpp -lCrypt32 -static -o bin/loot.exe