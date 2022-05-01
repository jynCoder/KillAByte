#ifndef SIT_AWARE
#define SIT_AWARE
#include <map>
#include <iostream>
#include <iphlpapi.h>

using namespace std;

map<string, string> retrieveEnvironmentStrings();
vector<string> getAdapterInfo();
string getWindowsVersion();
string getUserTokenSid();
string getUserName();
string getComputerName();
string getMachineGuid();
vector<string> getFilesInDirectory(string dirpath);
vector<string> getAllProcesses();
string setFileDirectory(string path);
#endif