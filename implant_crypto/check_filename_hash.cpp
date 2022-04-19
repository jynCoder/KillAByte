#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <iostream>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>

#define FILENAME "C:\\malware\\ch0nky.txt"
#define FILENAMELEN 21

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

	// 6. Convert to hex
	DWORD confirmSize;

    BOOL bufsizeCheck = CryptBinaryToStringA(
    	fileHash,
    	_msize(fileHash),
    	CRYPT_STRING_HEX,
    	NULL,
    	&confirmSize
    );

    if (bufsizeCheck == 0) {
    	std::cout << "[ERROR] Obtaining the correct size for the hex buffer failed." << std::endl;
    	return false;
    }

    LPSTR buf = (LPSTR) malloc(confirmSize * sizeof(LPSTR));

    BOOL bufCheck = CryptBinaryToStringA(
    	fileHash,
    	_msize(fileHash),
    	CRYPT_STRING_HEX | CRYPT_STRING_NOCRLF,
    	buf,
    	&confirmSize
    );

	// 6. Compare hash with desired hash
	std::string FILENAMEHASH = "f8 54 ae 18 4b f1 7d 97 c3 ae 33 91 a8 d4 94 96 5d 43 1b b4 65 05 08 09 9c 6e ce 4c 8c 40 43 43";

	BOOL out = false;
	if (FILENAMEHASH.compare(buf) == 0) {
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
		printf("Checking for hash of ch0nky.txt!\n");
		if (checkForFileHash()) {
			printf("ch0nky.txt hash found!\n");
		}
		else {
			printf("ch0nky.txt hash not found...\n");
		}
	}
	else {
		printf("ch0nky.txt file not found...\n");
	}
	return 0;
}