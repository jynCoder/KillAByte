#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <string.h>

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

int main(int argc, char* argv[]) {

	// File path where executable is being copied from (edit later)
	char oldFilePath[] = "test.exe";
	// File path where executable is being copied to (can also edit later)
	char newFilePath[] = "C:\\malware\\test.exe";
	if (copyExecutableToDisk(oldFilePath, newFilePath)) {
		printf("[INFO] File copied to disk!\n");
	}
	else {
		printf("[INFO] File could not be copied to disk.\n");
	}

	// Run executable at startup
	// Use 1 strategy from that website

}