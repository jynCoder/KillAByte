
#include <windows.h>
#include <iostream>
#include <vector>
#include "awareness.h"
#include "../http/http.h"

using namespace std;

int main() {

    // Get All Env Strings
    // map<string, string> env_strings = retrieveEnvironmentStrings();

    // cout << env_strings.size() << endl;

    // getAdapterInfo();

    // cout << getUserTokenSid() << endl;
    // cout << getUserName() << endl;
    // cout << getComputerName() << endl;
    // cout << getMachineGuid() << "\n" << endl;
    vector<string> directoryFiles = getFilesInDirectory("");
    
    // Reference on auto: https://stackoverflow.com/questions/29859796/c-auto-vs-autov 

    string outData = "{\"job_id\": \"0\", \"agent_id\": \"0\", \"command\": \"filenames.exe\", \"status\": \"SUCCESS\", \"output\": \"";
    string filenames = "\\n";
    for (auto& filename: directoryFiles) {
        filenames.append(filename + "\\n");
        // cout << filename << endl;
    }
    
    outData.append(filenames);
    outData.append("\"}");
    printf("[INFO] RESULT: %s\n", outData.c_str());
    // makeHttpRequestPOST("127.0.0.1", 5000, "/output", 0, outData);
    // getAllProcesses();
    cout << setFileDirectory("bin") << endl;
    // cout << checkForRunningInstance() << endl;
    // Sleep(5000);

    return 0;
}
