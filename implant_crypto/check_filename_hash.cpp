#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>

#define FILENAME "C:\\malware\\ch0nky.txt"
#define FILENAMELEN 22
// Obtained with: (Get-FileHash C:\malware\ch0nky.txt).Hash.ToLower()
// 25279a7b1e82c890e5a789f5d838a36a195c080c6565a7692f5ef40634a40aef
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

	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
			&algHandle,
			BCRYPT_SHA256_ALGORITHM,
			NULL,
			0))) {
		std::cout << "[ERROR] Could not initialize hashing handle." << std::endl;
    	return false;
	}

	// 2. Retrieve value of length for hashing object
	DWORD hashLen;
	ULONG result;
	if (!BCRYPT_SUCCESS(BCryptGetProperty(
			algHandle,
			BCRYPT_OBJECT_LENGTH,
			(PUCHAR)&hashLen,
			sizeof(hashLen),
			&result,
			0))) {
		std::cout << "[ERROR] Could not retrieve length for hashing object." << std::endl;
        BCryptCloseAlgorithmProvider(algHandle, 0);
        return false;
	}

	// 3. Allocate memory and create hash
	BCRYPT_HASH_HANDLE hashHandle;
	PUCHAR hashObj = (PUCHAR)malloc(hashLen);

	if (!BCRYPT_SUCCESS(BCryptCreateHash(
			algHandle,
			&hashHandle,
			hashObj,
			hashLen,
			NULL,
			0,
			0))) {
		std::cout << "[ERROR] Could not create hashing object." << std::endl;
        BCryptCloseAlgorithmProvider(algHandle, 0);
        BCryptDestroyHash(hashHandle);
        free(hashObj);
    	return false;
	}

	// 4. Create hash
	if (!BCRYPT_SUCCESS(BCryptHashData(
			hashHandle,
			(PUCHAR) FILENAME,
			FILENAMELEN,
			0))) {
		std::cout << "[ERROR] Could not hash file." << std::endl;
        BCryptCloseAlgorithmProvider(algHandle, 0);
        BCryptDestroyHash(hashHandle);
        free(hashObj);
    	return false;
	}

	// 5. Retrieve hash, length is 32 bytes or 64 hex chars
	PUCHAR fileHash = (PUCHAR)malloc(32);
	if (!BCRYPT_SUCCESS(BCryptFinishHash(
			hashHandle,
			fileHash,
			32,
			0))) {
		std::cout << "[ERROR] Could not retrieve file hash." << std::endl;
        BCryptCloseAlgorithmProvider(algHandle, 0);
        BCryptDestroyHash(hashHandle);
        free(hashObj);
        free(fileHash);
    	return false;
	}

	// 6. Compare hash with desired hash

	printf("%s\n", fileHash);
	printf("%s\n", FILEHASH);

	BOOL out;
	if (fileHashHex == FILEHASH) {
		out = true;
	}
	else {
		out = false;
	}

	// 7. Cleanup
    if (algHandle) {
        BCryptCloseAlgorithmProvider(algHandle, 0);
    }
	if (hashHandle) {
        BCryptDestroyHash(hashHandle);
    }
	if (hashObj) {
        free(hashObj);
    }
	if (fileHash) {
        free(fileHash);
    }

    return out;
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
		printf("ch0nky.txt hash not found...\n");
	}

	// if (checkForFile() && checkForFileHash()) {
	// 	printf("ch0nky.txt file exists and is verified.");
	// }
	// else {
	// 	printf("ch0nky.txt file does not exist and/or is not verified.\n");
	// }
	return 0;
}