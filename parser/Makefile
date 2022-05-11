CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

.PHONY: all parser.exe clean

parser.exe:
	$(CXX) parser.cpp  http.cpp parserCreateProcess.cpp -lwinhttp -static -o bin/parser.exe