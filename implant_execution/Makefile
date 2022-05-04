CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

.PHONY: all createProcess.exe injection.exe local_shellcode.exe clean

createProcess.exe:
	$(CXX) createProcess.cpp http.cpp -lwinhttp -static -o bin/createProcess.exe

injection.exe:
	$(CXX) injection.cpp http.cpp -lwinhttp -static -o bin/injection.exe

local_shellcode.exe:
	$(CXX) local_shellcode.cpp http.cpp -lwinhttp -static -o bin/local_shellcode.exe