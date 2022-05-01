CXX=g++
ifeq ($(OS),Windows_NT)
    RM = powershell /c rm
else
    RM = rm -f
    RRM = rm -f -r
endif

awareness_and_test:
	$(CXX) -g main.cpp awareness.cpp -o bin/main.exe -liphlpapi -lwsock32 -lws2_32
	bin/main.exe