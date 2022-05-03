#include <windows.h>
#include <string>
#include <iostream>
#include <winhttp.h>
#include <tuple>
#include <algorithm>

BOOL cleanUp(WINHTTPAPI HINTERNET httpOpenHandle, WINHTTPAPI HINTERNET httpConnectHandle, WINHTTPAPI HINTERNET httpOpenRequestHandle) {
    if (!WinHttpCloseHandle(httpOpenHandle)) {
        printf("[ERROR] Could not close open handle.");
        return FALSE;
    }

    if (!WinHttpCloseHandle(httpConnectHandle)) {
        printf("[ERROR] Could not close connection handle.");
        return FALSE;
    }

    if (!WinHttpCloseHandle(httpOpenRequestHandle)) {
        printf("[ERROR] Could not close openrequest handle.");
        return FALSE;
    }

    return TRUE;
}

std::tuple<HANDLE, HANDLE> initConnection(std::string fqdn, int port, std::string uri, bool useTLS) {
    // Init a WinHttp Session using WinHttpOpen
    WINHTTPAPI HINTERNET httpOpenHandle = WinHttpOpen(
        L"Not Suspicious User Agent",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_FLAG_ASYNC
    );

    if (httpOpenHandle == NULL) {
        printf("[ERROR] WinHttpOpen could not get a valid HTTP session handle.\n");
        if (!WinHttpCloseHandle(httpOpenHandle)) {
            return {NULL, NULL};
        }
        return {NULL, NULL};
    }

    // Convert domain to wide char for WinHttpConnect
    std::wstring fqdn_w = std::wstring(fqdn.begin(), fqdn.end());
    LPCWSTR server_name = fqdn_w.c_str();

    WINHTTPAPI HINTERNET httpConnectHandle = WinHttpConnect(
        httpOpenHandle,
        server_name,
        port,
        0
    );

    if (httpConnectHandle == NULL) {
        printf("[ERROR] WinHttpConnect could not get a valid HTTP connection handle.\n");
        if (!WinHttpCloseHandle(httpOpenHandle)) {
            return {NULL, NULL};
        }
        if (!WinHttpCloseHandle(httpConnectHandle)) {
            return {NULL, NULL};
        }

        return {NULL, NULL};
    }

    return {httpOpenHandle, httpConnectHandle};
}

std::string makeHttpRequestGET(std::string fqdn, int port, std::string uri, bool useTLS){
    std::string result;
    
    auto [httpOpenHandle, httpConnectHandle] = initConnection(fqdn, port, uri, useTLS);

    // Convert URI to wide char
    std::wstring uri_w = std::wstring(uri.begin(), uri.end());
    LPCWSTR object_name = uri_w.c_str();

    // Make sure to use flag "WINHTTP_FLAG_SECURE" if TLS is enabled, can differentiate between HTTP and HTTPS
    DWORD flags;
    if (useTLS) {
        flags = WINHTTP_FLAG_SECURE | WINHTTP_FLAG_ESCAPE_DISABLE;
    }
    else {
        flags = WINHTTP_FLAG_ESCAPE_DISABLE;
    }

    WINHTTPAPI HINTERNET httpOpenRequestHandle = WinHttpOpenRequest(
        httpConnectHandle,
        NULL, //For a GET request
        object_name,
        NULL, //Set version to HTTP/1.1, default
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, //only accept text
        flags
    );

    if (httpOpenRequestHandle == NULL) {
        printf("[ERROR] WinHttpOpenRequest could not get a valid HTTP request handle.\n");
        if (!cleanUp(httpOpenHandle, httpConnectHandle, httpOpenRequestHandle)) {
            return result;
        }
        return result; //Returns nothing
    }

    DWORD test_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    // Set flags for testing
    BOOL optionCheck = WinHttpSetOption(
        httpOpenRequestHandle,
        WINHTTP_OPTION_SECURITY_FLAGS,
        &test_flags,
        sizeof(test_flags)
    );

    if (!optionCheck) {
        printf("[ERROR] WinHttpSetOption could not set flags properly.\n");
        if (!cleanUp(httpOpenHandle, httpConnectHandle, httpOpenRequestHandle)) {
            return result;
        }
        return result; //Returns nothing
    }

    //Now, send request
    BOOL checkSentRequest = WinHttpSendRequest(
        httpOpenRequestHandle,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    );

    if (!checkSentRequest) {
        printf("[ERROR] WinHttpSendRequest failed to send a request.\n");
        if (!cleanUp(httpOpenHandle, httpConnectHandle, httpOpenRequestHandle)) {
            return result;
        }
        return result; //Returns nothing
    }

    //Receive response
    WINHTTPAPI BOOL checkRecvResponse = WinHttpReceiveResponse(
        httpOpenRequestHandle,
        NULL);

    if (!checkRecvResponse) {
        printf("[ERROR] WinHttpReceiveResponse failed to receive a response.\n");
        if (!cleanUp(httpOpenHandle, httpConnectHandle, httpOpenRequestHandle)) {
            return result;
        }
        return result; //Result not allocated yet so returns nothing
    }

    // Make fixed character buffer
    int BUF_SIZE = 4096;
    char* buf = (char*) malloc(BUF_SIZE); //char has size of 1 byte

    // Allocate variables necessary to query data available and then read that into our buffer
    DWORD bytesRecv;
    DWORD bytesRead;
    BOOL checkReadData;

    do {
        if (!WinHttpQueryDataAvailable(httpOpenRequestHandle, &bytesRecv)) {
            break;
        }
        if (bytesRecv == 0) {
            break;
        }
        if (WinHttpReadData(httpOpenRequestHandle, buf, bytesRecv, &bytesRead)) {
            result += buf;
            char* buf = (char*) malloc(BUF_SIZE); // Reset buf each iteration
        }
    } while (bytesRecv > 0);

    buf[BUF_SIZE - 1] = '\0'; //Make sure buffer is null terminated

    // Cleanup (See cleanUp() function above)
    if (!cleanUp(httpOpenHandle, httpConnectHandle, httpOpenRequestHandle)) {
        return ""; //Result holds info so do not return it, return nothing on error
    }

    return result;
}

std::string makeHttpRequestPOST(std::string fqdn, int port, std::string uri, bool useTLS, std::string data){
    std::string result;
    
    auto [httpOpenHandle, httpConnectHandle] = initConnection(fqdn, port, uri, useTLS);

    // Convert URI to wide char
    std::wstring uri_w = std::wstring(uri.begin(), uri.end());
    LPCWSTR object_name = uri_w.c_str();

    // Make sure to use flag "WINHTTP_FLAG_SECURE" if TLS is enabled, can differentiate between HTTP and HTTPS
    DWORD flags;
    if (useTLS) {
        flags = WINHTTP_FLAG_SECURE | WINHTTP_FLAG_ESCAPE_DISABLE;
    }
    else {
        flags = WINHTTP_FLAG_ESCAPE_DISABLE;
    }

    WINHTTPAPI HINTERNET httpOpenRequestHandle = WinHttpOpenRequest(
        httpConnectHandle,
        L"POST", //For a POST request
        object_name,
        NULL, //Set version to HTTP/1.1, default
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, //only accept text
        flags
    );

    if (httpOpenRequestHandle == NULL) {
        printf("[ERROR] WinHttpOpenRequest could not get a valid HTTP request handle.\n");
        if (!cleanUp(httpOpenHandle, httpConnectHandle, httpOpenRequestHandle)) {
            return result;
        }
        return result; //Returns nothing
    }

    DWORD test_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    // Set flags for testing
    BOOL optionCheck = WinHttpSetOption(
        httpOpenRequestHandle,
        WINHTTP_OPTION_SECURITY_FLAGS,
        &test_flags,
        sizeof(test_flags)
    );

    if (!optionCheck) {
        printf("[ERROR] WinHttpSetOption could not set flags properly.\n");
        if (!cleanUp(httpOpenHandle, httpConnectHandle, httpOpenRequestHandle)) {
            return result;
        }
        return result; //Returns nothing
    }

    // Make sure correct header is there: JSON
    LPCWSTR header = L"Content-Type: application/json\r\n";

    // std::string dataTest = "{\"type\": \"powershell\", \"cmd\": \"whoami\", \"agent_id\": \"1\"}";

    // Replace single quotes with double quotes
    std::replace(data.begin(), data.end(), '\'', '\"');

    printf("Data: %s\n", data.c_str());
    printf("Len: %d\n", data.length());

    //Now, send request
    BOOL checkSentRequest = WinHttpSendRequest(
        httpOpenRequestHandle,
        header,
        -1,
        (LPVOID)data.c_str(),
        data.length(),
        data.length(),
        0
    );

    printf("%x\n", GetLastError());

    if (!checkSentRequest) {
        printf("[ERROR] WinHttpSendRequest failed to send a request.\n");
        if (!cleanUp(httpOpenHandle, httpConnectHandle, httpOpenRequestHandle)) {
            return result;
        }
        return result; //Returns nothing
    }

    //Receive response
    WINHTTPAPI BOOL checkRecvResponse = WinHttpReceiveResponse(
        httpOpenRequestHandle,
        NULL);

    if (!checkRecvResponse) {
        printf("[ERROR] WinHttpReceiveResponse failed to receive a response.\n");
        if (!cleanUp(httpOpenHandle, httpConnectHandle, httpOpenRequestHandle)) {
            return result;
        }
        return result; //Result not allocated yet so returns nothing
    }

    // Make fixed character buffer
    int BUF_SIZE = 4096;
    char* buf = (char*) malloc(BUF_SIZE); //char has size of 1 byte

    // Allocate variables necessary to query data available and then read that into our buffer
    DWORD bytesRecv;
    DWORD bytesRead;
    BOOL checkReadData;

    do {
        if (!WinHttpQueryDataAvailable(httpOpenRequestHandle, &bytesRecv)) {
            break;
        }
        if (bytesRecv == 0) {
            break;
        }
        if (WinHttpReadData(httpOpenRequestHandle, buf, bytesRecv, &bytesRead)) {
            result += buf;
            char* buf = (char*) malloc(BUF_SIZE); // Reset buf each iteration
        }
    } while (bytesRecv > 0);

    buf[BUF_SIZE - 1] = '\0'; //Make sure buffer is null terminated

    // Cleanup (See cleanUp() function above)
    if (!cleanUp(httpOpenHandle, httpConnectHandle, httpOpenRequestHandle)) {
        return ""; //Result holds info so do not return it, return nothing on error
    }

    return result;
}

int main(int argc, char* argv[]) {
    if (argc != 7) {
        printf("[ERROR] Wrong number of arguments.\n");
        printf("[INFO] Syntax: http.exe (fqdn) (port) (uri) (use_tls) (get/post = 0/1) (data)\n");
        printf("[INFO] For JSON requests, please use single quotes.\n");
        return 0;
    }

    std::string fqdn = std::string(argv[1]);
    int port = std::stoi(argv[2]);
    std::string uri = std::string(argv[3]);
    int useTLS =std::stoi(argv[4]);
    int getOrPost = std::stoi(argv[5]);
    std::string data = std::string(argv[6]);

    bool tls;
    bool getPost;
    
    if (useTLS == 1) {
        tls = true;
    } 
    else if (useTLS == 0) {
        tls = false;
    } 
    else {
        printf("[ERROR] Bad value for useTLS (must be 0/1)\n");
        return 0;
    }

    if (getOrPost == 1) {
        getPost = true; //POST req
    }
    else if (getOrPost == 0) {
        getOrPost = false; //GET req
    }
    else {
        printf("[ERROR] Bad value for GET/POST argument (must be 0/1 where 0 = GET, 1 = POST)\n");
        return 0;
    }

    if (getPost) {
        std::cout << makeHttpRequestPOST(fqdn, port, uri, tls, data) << std::endl;
    }
    else {
        std::cout << makeHttpRequestGET(fqdn, port, uri, tls) << std::endl;
    }
    return 0;
}