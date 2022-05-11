CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

.PHONY: all persistence.exe clean

persistence.exe:
	$(CXX) persistence.cpp http.cpp -lwinhttp -static -o bin/persistence.exe