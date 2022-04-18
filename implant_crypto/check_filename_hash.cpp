#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <iostream>

#define FILENAME "C:\\malware\\ch0nky.txt"
// Obtained with: (Get-FileHash C:\malware\ch0nky.txt).Hash.ToLower()
#define FILEHASH "25279a7b1e82c890e5a789f5d838a36a195c080c6565a7692f5ef40634a40aef"

BOOL checkForFile() {
	if (PathFileExistsA(FILENAME)) {
		return true;
	}
	else {
		return false;
	}
}

BOOL checkForFileHash() {
	// 1. Initalize a CNG (cryptography next-genertion) provider for SHA256
	NTSTATUS status;
	BCRYPT_ALG_HANDLE algHandle;

	if (BCryptOpenAlgorithmProvider(
			algHandle,
			BCRYPT_SHA256_ALGORITHM,
			NULL,
			0) == STATUS_SUCCESS) {
		std::cout << "[ERROR] Could not initialize hashing handle." << std::endl;
    	return false;
	}

	// 2. Retrieve value of length for hashing object
	PUCHAR hashLen;
	if (BCryptGetProperty(
			algHandle,
			BCRYPT_OBJECT_LENGTH,
			hashLen,
			sizeof(hashLen),
			NULL,
			0) == STATUS_SUCCESS) {
		std::cout << "[ERROR] Could not retrieve length for hashing object." << std::endl;
    	return false;
	}

	// 3. Allocate memory and create hash
	BCRYPT_HASH_HANDLE hashHandle;
	PUCHAR hashObj = malloc(hashLen);

	if (BCryptCreateHash(
			algHandle,
			&hashHandle,
			hashObj,
			(ULONG) hashLen,
			NULL,
			0,
			0) == STATUS_SUCCESS) {
		std::cout << "[ERROR] Could not create hashing object." << std::endl;
    	return false;
	}

	// 4. Retrieve hash
	// if (BCryptFinishHash(
	// 		&hashHandle,
	// 		hashObj,
	// 		(ULONG) hashLen,
	// 		NULL,
	// 		0,
	// 		0) 
	// 	!= STATUS_SUCCESS) {
	// 	std::cout << "[ERROR] Could not create hashing object." << std::endl;
 //    	return false;
	// }

	printf("%s\n", hashObj);
}

int main(int argc, char* argv[]) {
	printf("Checking for ch0nky.txt!\n");
	if (checkForFile()) {
		printf("ch0nky.txt file found!\n");
	}
	else {
		printf("ch0nky.txt file not found...\n");
	}

	printf("Checking for hash of ch0nky.txt!\n");
	if (checkForFileHash()) {
		printf("ch0nky.txt hash found!\n");
	}
	else {
		printf("ch0nky.txt hash found...\n");
	}

	if (checkForFile() && checkForFileHash()) {
		printf("ch0nky.txt file exists and is verified.");
	}
	else {
		printf("ch0nky.txt file does not exist and/or is not verified.\n");
	}
}