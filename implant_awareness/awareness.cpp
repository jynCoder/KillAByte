#include <winsock2.h>
#include <iostream>
#include <map>
#include <vector>
#include <iostream>
#include <iphlpapi.h>
#include <iptypes.h>
#include <windows.h>
#include <sddl.h>
#include <Lmcons.h>
#include <tlhelp32.h>

// #ifndef UNICODE  
//   typedef std::string String; 
// #else
//   typedef std::wstring String; 
// #endif


using namespace std;

map<string, string> retrieveEnvironmentStrings() {
    map<string, string> ret;

    LPTCH strings = GetEnvironmentStrings();

    char *cur_string = strings;
    size_t len = strlen(cur_string);
    while (len > 0) {
        // Convert to STL String
        string cur_str = string(cur_string);

        // Assume format is "A=B"
        size_t delim = cur_str.find('=');
        string key = cur_str.substr(0, delim);
        string val = cur_str.substr(delim+1, cur_str.size());

        ret[key] = val;

        cur_string += len + 1;
        len = strlen(cur_string);
    }

    FreeEnvironmentStrings(strings);

    return ret;
}

vector<string> getAdapterInfo() {
    // TODO: This function only prints the adapter info. We need
    // to put them in strings and return them.
    
    vector<string> adapterInfo;
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
    PIP_ADAPTER_MULTICAST_ADDRESS pMulticast = NULL;

    // Should be enough
    ULONG bufSize = 15000;
    PIP_ADAPTER_ADDRESSES out = (IP_ADAPTER_ADDRESSES*)malloc(bufSize);
    ULONG retVal = GetAdaptersAddresses(AF_INET, 0, NULL, out, &bufSize);
    
    if (retVal != NO_ERROR) {
        cout << "Error getting adapters" << endl;

    }

    unsigned int i = 0;

    PIP_ADAPTER_ADDRESSES pCurrAddresses = out;
    while (pCurrAddresses) {
        pUnicast = pCurrAddresses->FirstUnicastAddress;
        while (pUnicast) {
            ULONG addrLen = 0;

            WSAAddressToString(
                pUnicast->Address.lpSockaddr,
                pUnicast->Address.iSockaddrLength,
                NULL,
                NULL,
                &addrLen);

            // We now have a valid addrLen.
            char buf[addrLen + 1] = {};
            if (WSAAddressToString(
                    pUnicast->Address.lpSockaddr,
                    pUnicast->Address.iSockaddrLength,
                    NULL,
                    buf,
                    &addrLen) != 0) {
                printf("Failed: %i\n", WSAGetLastError());
            }

            cout << buf << endl;

            pUnicast = pUnicast->Next;
        }

        wcout << pCurrAddresses->FriendlyName << endl;
        pCurrAddresses = pCurrAddresses->Next; 
    }

    if (out) {
        free(out);
    }

    return adapterInfo;
}

string getWindowsVersion() {
    DWORD dwVersion = 0; 
    DWORD dwMajorVersion = 0;
    DWORD dwMinorVersion = 0; 
    DWORD dwBuild = 0;

    dwVersion = GetVersion();
 
    // Get the Windows version.

    dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
    dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

    // Get the build number.

    if (dwVersion < 0x80000000)              
        dwBuild = (DWORD)(HIWORD(dwVersion));

    char buf[100];
    snprintf(
        buf,
        sizeof(buf),
        "Version is %d.%d (%d)\n", 
        dwMajorVersion,
        dwMinorVersion,
        dwBuild);

    return string(buf);
}

string getUserTokenSid() {
    HANDLE tokenHandle;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &tokenHandle)) {
        cout << "Failed to get user token." << endl;
        printf("%d\n", GetLastError());
        return "unknown";
    }

    TOKEN_USER tokenUser;
    ULONG returnLen;
    if (!GetTokenInformation(tokenHandle, TokenUser, &tokenUser, 1024, &returnLen)) {
        printf("Failed getting TOKEN_USER. %d\n", GetLastError());
        return "unknown";
    }

    LPTSTR sid = NULL;
    ConvertSidToStringSid(tokenUser.User.Sid, &sid);

    string ret(sid);

    LocalFree(sid);
    CloseHandle(tokenHandle);
    return ret;
}

string getUserName() {
    char username[UNLEN+1];
    DWORD username_len = UNLEN+1;

    GetUserName(username, &username_len);
    return string(username);
}

string getComputerName() {
    char computerName[32767];
    DWORD len = 32767;
    GetComputerName(computerName, &len);
    return string(computerName);
}

string getMachineGuid() {
    HKEY hKey = 0;
	char buf[255]={0};
	DWORD dwType = 0;
	DWORD dwBufSize = 255;
	const char* subkey = "Software\\Microsoft\\Cryptography";
    string machineGuid;

    if( RegOpenKey(HKEY_LOCAL_MACHINE,subkey,&hKey) == ERROR_SUCCESS) {
		dwType = REG_SZ;
		if (RegQueryValueEx(hKey,"MachineGuid",0, &dwType, (BYTE*)buf, &dwBufSize)== ERROR_SUCCESS) {
            machineGuid = string(buf);
		}
		RegCloseKey(hKey);
	}
    return machineGuid;
}

/**
 * @brief Retrieves all files in a given directory
 * 
 * @param dirpath directory path, do not add backslash at the end. If empty string, will get files in current drive
 * @return vector<string> 
 */
vector<string> getFilesInDirectory(string dirpath) {
    vector<string> files;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA ffd;

    hFind = FindFirstFile((dirpath + "\\*").c_str(), &ffd);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Error finding first file.");
        return files;
    }

    do {
        files.push_back(string(ffd.cFileName));
    } while (FindNextFile(hFind, &ffd) != 0);

    if (GetLastError() != ERROR_NO_MORE_FILES) {
        cout << "Failed to find next file. " << GetLastError() << endl;
    }

    FindClose(hFind);
    return files;
}

vector<string> getAllProcesses() {
    vector<string> allProcesses;
    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshotHandle == INVALID_HANDLE_VALUE) {
        printf("Failed to get all processes.");
    }

    PROCESSENTRY32 pe;

    if (Process32First(snapshotHandle, &pe)) {
        do {
            allProcesses.push_back(string(pe.szExeFile));
        } while (Process32Next(snapshotHandle, &pe));
    }

    CloseHandle(snapshotHandle);
    return allProcesses;
}

/**
 * @brief Changes the file directory and returns a string 
 * representation of the file path
 * 
 * Make sure to escape \ character.
 * Examples: 
 * \\
 * C:\\
 * ..\\
 * bin
 * @return string 
 */
string setFileDirectory(string path) {

    const int BUFSIZE = MAX_PATH;
    char buffer[BUFSIZE];
    DWORD dwRet;

    if (!SetCurrentDirectory(path.c_str())) {
        printf("SetCurrentDirectory failed (%d)\n", GetLastError());
    }
    dwRet = GetCurrentDirectory(BUFSIZE, buffer);
    if( dwRet == 0 ) {
        printf("GetCurrentDirectory failed (%d)\n", GetLastError());
    }
    return string(buffer);
}