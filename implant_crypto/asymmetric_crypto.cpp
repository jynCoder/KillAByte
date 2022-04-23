#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <iostream>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>

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

BYTE* encryptRSA(BCRYPT_KEY_HANDLE keyHandle, std::string plainText) {
	//Args:
	//	keyHandle - key handle generated in generateKeyRSA()
	//	plaintext - text to encrypt (string for now)

	//1. Encrypt using RSA key

	// Need size required for ciphertext
    ULONG confirmSize;
    // Convert string input into PUCHAR for BCryptEncrypt
    char* plaintext_chars = const_cast<char*>(plainText.c_str());

	if (!BCRYPT_SUCCESS(BCryptEncrypt(
			keyHandle,
			(PUCHAR) plaintext_chars,
			plainText.length(),
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

    BYTE* encryptedText = NULL;

    // With size, can encrypt
    if (!BCRYPT_SUCCESS(BCryptEncrypt(
			keyHandle,
			(PUCHAR) plaintext_chars,
			plainText.length(),
			NULL,
			NULL,
			0,
			(PUCHAR) encryptedText,
			confirmSize,
			&confirmSize,
			BCRYPT_PAD_NONE))) {
		std::cout << "[ERROR] RSA encryption failed (generating encrypted text)." << std::endl;
		cleanUp();
		return NULL;
	}

    return encryptedText;
}

//TODO
bool decryptRSA() {
	return true;
}

int main(int argc, char* argv[]) {
	printf("[INFO] Testing RSA!\n");
	BCRYPT_KEY_HANDLE keyHandle = generateKeyRSA();
	if (keyHandle) {
		printf("[INFO] Key pair successfully generated!\n");
	}

	std::string plaintext_test = "CS501: Introduction to Malware, Threat Hunting and Offensive Capabilities Development";
	BYTE* encryptedText = encryptRSA(keyHandle, plaintext_test);

	//TODO: Fix
	if (encryptedText) {
		printf("[INFO] Plaintext successfully encrypted!\n");
	}

	//TODO: Decryption

	cleanUp();
	return 0;
}