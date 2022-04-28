#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <string.h>

std::string getChromeContents() {
	// Get current user (for the filepath)
	// 256 is max username length (see lmcons.h)
	DWORD bufSize = 256 + 1;
	char* userBuf = (char*) malloc(bufSize);

	if (GetUserNameA(userBuf, &bufSize) == 0) {
		printf("[ERROR] Could not retrieve username.");
	}

	userBuf[bufSize] = '\0';
	// printf("%s\n", userBuf);

	// Get filepath
	std::string filePath = "C:\\Users\\";
	std::string userName = userBuf;
	std::string endPath = "\\AppData\\Local\\Google\\User Data\\Local State";

	filePath.append(userName);
	filePath.append(endPath);

	// printf("%s\n", filePath.c_str());

	// Get file handle with CreateFile (doesn't actually create a file, it just opens one)
	HANDLE fileHandle = CreateFileA(
		(LPCSTR) filePath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING, //Only open if file exists, end process if file does not exist
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (fileHandle == INVALID_HANDLE_VALUE) {
		printf("[INFO] No Google Chrome data.\n");
		return "";
	}

	printf("TODO\n");

	//Cleanup
	CloseHandle(fileHandle);

	return "";
}

int main(int argc, char* argv[]) {
	// Access folder C:\Users\<User>\AppData\Local\Google\User Data
	// "Local State" is the file

	// getChromeContents(): get contents of JSON file "Local State"

	std::string chromeContents = getChromeContents();

	// JSON file with secret key, encrypted with data protection api (DPAPI)
	// To decrypt:
	// Parse encrypted (symmetric) key
	// Decrypt with DPAPI
	// Decrypt data in SQLite database
}