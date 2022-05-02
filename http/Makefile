CC=gcc
CXX=g++

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else	
	RM=rm
endif

all: http.exe 

.PHONY: all clean 

http.exe:
	$(CXX) http.cpp -lwinhttp -static -o bin/http.exe