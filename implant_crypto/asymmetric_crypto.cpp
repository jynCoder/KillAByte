#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <iostream>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

BCRYPT_ALG_HANDLE algHandle;
BCRYPT_KEY_HANDLE keyHandle;

void cleanUp() {
	if (algHandle) {
		BCryptCloseAlgorithmProvider(algHandle, 0);
		algHandle = NULL;
	}
	if (keyHandle) {
		BCryptDestroyKey(keyHandle);
		keyHandle = NULL;
	}
}

BCRYPT_KEY_HANDLE generateKeyRSA() {
	// 1. Initalize a CNG (cryptography next-genertion) provider for RSA
	NTSTATUS status;

	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
			&algHandle,
			BCRYPT_RSA_ALGORITHM,
			NULL,
			0))) {
		std::cout << "[ERROR] Could not initialize RSA handle." << std::endl;
		cleanUp();
    	return NULL;
	}

	// Can also generate keys with BCryptImportKey or BCryptImportKeyPair
	// We will probably use this instead. If this is the case, I can
	// make a new function.

	// 2. Generate key pair for RSA

	if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(
			algHandle,
			&keyHandle,
			512, //Key length is 512, can be adjusted here
			0))) {
		std::cout << "[ERROR] Key pair for RSA could not be generated." << std::endl;
		cleanUp();
		return NULL;
	}


	// 2.5. Set key properties? Not sure if necessary.

	// 3. Finalize key pair 
	if (!BCRYPT_SUCCESS(BCryptFinalizeKeyPair(
			keyHandle,
			0))) {
		std::cout << "[ERROR] Key pair for RSA could not be finalized." << std::endl;
		cleanUp();
		return NULL;
	}

	return keyHandle;
}

char* encryptRSA(BCRYPT_KEY_HANDLE keyHandle, char* plainText) {
	//Args:
	//	keyHandle - key handle generated in generateKeyRSA()
	//	plainText - text to encrypt (string for now)

	//1. Obtain size required for ciphertext
    ULONG confirmSize;

	if (!BCRYPT_SUCCESS(BCryptEncrypt(
			keyHandle,
			(PUCHAR) plainText,
			(ULONG) strlen(plainText),
			NULL,
			NULL,
			0,
			NULL,
			0,
			&confirmSize,
			BCRYPT_PAD_NONE))) {
		std::cout << "[ERROR] RSA encryption failed (obtaining size for encrypted text)." << std::endl;
		cleanUp();
		return NULL;
	}

	// printf("confirmSize: ");
    // printf("%lu\n", confirmSize);

	// Create buffer with retrieved size
    char* encryptedText = (char*) malloc(confirmSize + 1);
    ULONG confirmData;

    // 2. With size, can encrypt
    if (!BCRYPT_SUCCESS(BCryptEncrypt(
			keyHandle,
			(PUCHAR) plainText,
			(ULONG) strlen(plainText),
			NULL,
			NULL,
			0,
			(PUCHAR) encryptedText,
			confirmSize + 1,
			&confirmData,
			BCRYPT_PAD_NONE))) {
		std::cout << "[ERROR] RSA encryption failed (generating encrypted text)." << std::endl;
		cleanUp();
		return NULL;
	}

	// printf("%s\n", encryptedText);

    return encryptedText;
}

//TODO
char* decryptRSA(BCRYPT_KEY_HANDLE keyHandle, char* encryptedText) {
	//Args:
	//	keyHandle - key handle generated in generateKeyRSA()
	//	encryptedText - text to decrypt (char* for now)

	// 1. Obtain size required for plaintext
	ULONG confirmSize;

	if (!BCRYPT_SUCCESS(BCryptDecrypt(
			keyHandle,
			(PUCHAR) encryptedText,
			(ULONG) strlen(encryptedText),
			NULL,
			NULL,
			0,
			NULL,
			0,
			&confirmSize,
			BCRYPT_PAD_NONE))) {
		std::cout << "[ERROR] RSA decryption failed (obtaining size for decrypted text)." << std::endl;
		cleanUp();
		return NULL;
	}

	printf("confirmSize: ");
    printf("%lu\n", confirmSize);

    char* plainText = (char*) malloc(confirmSize + 1);
    ULONG confirmData;

    if (!BCRYPT_SUCCESS(BCryptDecrypt(
			keyHandle,
			(PUCHAR) encryptedText,
			(ULONG) strlen(encryptedText),
			NULL,
			NULL,
			0,
			(PUCHAR) plainText,
			confirmSize + 1,
			&confirmData,
			BCRYPT_PAD_NONE))) {
		std::cout << "[ERROR] RSA decryption failed (obtaining size for decrypted text)." << std::endl;
		cleanUp();
		return NULL;
	}

	plainText[confirmSize] = '\0';

    return plainText;
}

int main(int argc, char* argv[]) {
	printf("[INFO] Testing RSA!\n");
	BCRYPT_KEY_HANDLE keyHandle = generateKeyRSA();
	if (keyHandle) {
		printf("[INFO] Key pair successfully generated!\n");
	}

	char plaintext_test[] = "CS501: Introduction to Malware, Threat Hunting and Offensive Capabilities Development";
	char* encryptedText = encryptRSA(keyHandle, plaintext_test);

	if (encryptedText) {
		printf("[INFO] Plaintext successfully encrypted!\n");
	}

	char* decryptedText = decryptRSA(keyHandle, encryptedText);

	if (strlen(decryptedText) != 0) {
		printf("[INFO] Encrypted text successfully decrypted!\n");
		printf("%s\n", decryptedText);
	}

	cleanUp();
	return 0;
}