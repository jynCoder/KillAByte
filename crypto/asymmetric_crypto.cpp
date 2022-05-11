#include "http.h"

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

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
	std::string outData = "";
	// 1. Initalize a CNG (cryptography next-genertion) provider for RSA
	NTSTATUS status;

	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
			&algHandle,
			BCRYPT_RSA_ALGORITHM,
			NULL,
			0))) {
		//std::cout << "[ERROR] Could not initialize RSA handle." << std::endl;
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Could not initialize RSA handle.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
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
			1024, //Key length is 1024, can be adjusted here
			0))) {
		//std::cout << "[ERROR] Key pair for RSA could not be generated." << std::endl;
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Key pair for RSA could not be generated.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		cleanUp();
		return NULL;
	}


	// 2.5. Set key properties? Not sure if necessary.

	// 3. Finalize key pair 
	if (!BCRYPT_SUCCESS(BCryptFinalizeKeyPair(
			keyHandle,
			0))) {
		//std::cout << "[ERROR] Key pair for RSA could not be finalized." << std::endl;
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Key pair for RSA could not be finalized.\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		cleanUp();
		return NULL;
	}

	return keyHandle;
}

char* encryptRSA(BCRYPT_KEY_HANDLE keyHandle, char* plainText) {
	std::string outData = "";
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
			BCRYPT_PAD_PKCS1))) {
		//std::cout << "[ERROR] RSA encryption failed (obtaining size for encrypted text)." << std::endl;
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] RSA encryption failed (obtaining size for encrypted text).\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		cleanUp();
		return NULL;
	}

	// printf("confirmSize: ");
    // printf("%lu\n", confirmSize);

	// Create buffer with retrieved size
    char* encryptedText = (char*) malloc(confirmSize + 1);
    ULONG confirmData;

    // 2. With size, can encrypt
    NTSTATUS result = BCryptEncrypt(
			keyHandle,
			(PUCHAR) plainText,
			(ULONG) strlen(plainText),
			NULL,
			NULL,
			0,
			(PUCHAR) encryptedText,
			confirmSize,
			&confirmData,
			BCRYPT_PAD_PKCS1);

    if (!BCRYPT_SUCCESS(result)) {
		//std::cout << "[ERROR] RSA encryption failed (generating encrypted text)." << std::endl;
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] RSA encryption failed (generating encrypted text).\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		cleanUp();
		return NULL;
	}

	encryptedText[confirmSize] = '\0';
	// printf("%s\n", encryptedText);

    return encryptedText;
}

char* decryptRSA(BCRYPT_KEY_HANDLE keyHandle, char* encryptedText) {
	std::string outData = "";
	//Args:
	//	keyHandle - key handle generated in generateKeyRSA()
	//	encryptedText - text to decrypt (char* for now)

	// 1. Obtain size required for plaintext
	ULONG confirmSize;

	NTSTATUS result = BCryptDecrypt(
			keyHandle,
			(PUCHAR) encryptedText,
			(ULONG) strlen(encryptedText),
			NULL,
			NULL,
			0,
			NULL,
			0,
			&confirmSize,
			BCRYPT_PAD_PKCS1);

	if (!BCRYPT_SUCCESS(result)) {
		//std::cout << "[ERROR] RSA decryption failed (obtaining size for decrypted text)." << std::endl;
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] RSA decryption failed (obtaining size for decrypted text).\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		cleanUp();
		return NULL;
	}

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
			confirmSize,
			&confirmData,
			BCRYPT_PAD_PKCS1))) {
		//std::cout << "[ERROR] RSA decryption failed (obtaining size for decrypted text)." << std::endl;
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] RSA decryption failed (decryption with decrypted text size).\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		cleanUp();
		return NULL;
	}

	plainText[confirmSize] = '\0';

    return plainText;
}

int main(int argc, char* argv[]) {
	std::string outData = "";

	if (argc != 3) {
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Syntax, need 3 arguments: (.\\asymmetric_crypto.exe) (text) (0/1 = encrypt/decrypt)\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
	}

	//Input parsing...
	std::string text_in = std::string(argv[1]);
    int encOrDec = std::stoi(argv[2]);

    bool doDecrypt;
    
    if (encOrDec == 1) {
        doDecrypt = true;
    } 
    else if (encOrDec == 0) {
        doDecrypt = false;
    } 
    else {
        //printf("[ERROR] Bad value for 3rd argument (must be 0/1 = encrypt/decrypt)\n");
        outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Bad value for 3rd argument (must be 0/1 = encrypt/decrypt)\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
        return 0;
    }

	//printf("[INFO] Testing RSA!\n");
	BCRYPT_KEY_HANDLE keyHandle = generateKeyRSA();
	if (keyHandle) {
		//printf("[INFO] Key pair successfully generated!\n");
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'INFO\', \'output\': \'[INFO] Key pair successfully generated!\'}";
        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
	}

	//char plaintext_test[] = "CS501: Introduction to Malware, Threat Hunting and Offensive Capabilities Development";

	if (!doDecrypt) {
		char* encryptedText = encryptRSA(keyHandle, const_cast<char*>(text_in.c_str()));

		if (encryptedText) {
			//printf("[INFO] Plaintext successfully encrypted!\n");
			outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'INFO\', \'output\': \'[INFO] Plaintext successfully encrypted!\'}";
	        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		}
	}
	else {
		char* decryptedText = decryptRSA(keyHandle, const_cast<char*>(text_in.c_str()));

		if (strlen(decryptedText) != 0) {
			//printf("[INFO] Encrypted text successfully decrypted!\n");
			//printf("%s\n", decryptedText);
			outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'asymmetric_crypto.exe\', \'status\': \'INFO\', \'output\': \'[INFO] Encrypted text successfully decrypted: ";
			outData.append(decryptedText);
			outData.append("\'}");
	        makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		}
	}

	cleanUp();
	return 0;
}