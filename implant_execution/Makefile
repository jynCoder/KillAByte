CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

.PHONY: all createProcess.exe clean

createProcess.exe:
	$(CC) createProcess.c -o bin/createProcess.exe

injection.exe:
	$(CXX) injection.cpp -o bin/injection.exe