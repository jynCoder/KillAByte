#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {

	if (argc != 3) {
		printf("[ERROR] Invalid argument/s.\n");
        printf("[INFO] Usage: ...\\injection.cpp [pid] [DLL path]\n");
        return 0;
    }

    // Get process by PID
    int pid = std::stoi(argv[1]);
    HANDLE pHandle = OpenProcess(
    	PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
    	FALSE,
    	pid);

    if (!pHandle) {
    	printf("[ERROR] Could not open requested process.\n");
    	return 0;
    }

    // Allocate memory
    int bufSize = 8192; // Arbitrary buffer size, can be adjusted
    LPVOID buf = VirtualAllocEx(
    		pHandle,
    		NULL,
    		bufSize,
    		MEM_COMMIT | MEM_RESERVE,
    		PAGE_EXECUTE_READWRITE
    	);

    if (!buf) {
    	printf("[ERROR] Could not allocate process memory.\n");
    	CloseHandle(pHandle);
    	return 0;
    }

    int dllPathSize = strlen(argv[2]) + 1;
    BOOL memCheck = WriteProcessMemory(
    		pHandle,
    		buf,
    		argv[2],
    		dllPathSize,
    		NULL);

    if (!memCheck) {
    	printf("[ERROR] Could not write process memory.\n");
    	CloseHandle(pHandle);
    	return 0;
    }

    // Create remote thread, load DLL
    LPTHREAD_START_ROUTINE startAddr = (LPTHREAD_START_ROUTINE)(GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA"));
    DWORD threadId;

    HANDLE tHandle = CreateRemoteThread(
    		pHandle,
    		NULL,
    		0,
    		startAddr,
    		buf,
    		0,
    		&threadId);

    if (!tHandle) {
    	printf("[ERROR] Could not create remote thread.\n");
    	CloseHandle(pHandle);
    	return 0;
    }

    // Wait for thread to finish
    DWORD threadTime = 10; // Time to wait in seconds, can be adjusted
    DWORD threadCheck = WaitForSingleObject(
    		tHandle,
    		threadTime * 1000);

    // Cleanup
    VirtualFreeEx(
    	pHandle, 
    	buf, 
    	0, 
    	MEM_RELEASE);

    CloseHandle(pHandle);
    CloseHandle(tHandle);

	return 0;
}