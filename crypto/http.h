#pragma once
#ifndef HTTP_H
#define HTTP_H

#include <windows.h>
#include <string>
#include <iostream>
#include <winhttp.h>
#include <tuple>
#include <algorithm>

BOOL cleanUp(WINHTTPAPI HINTERNET httpOpenHandle, WINHTTPAPI HINTERNET httpConnectHandle, WINHTTPAPI HINTERNET httpOpenRequestHandle);

std::tuple<HANDLE, HANDLE> initConnection(std::string fqdn, int port, std::string uri, bool useTLS);
std::string makeHttpRequestGET(std::string fqdn, int port, std::string uri, bool useTLS);
std::string makeHttpRequestPOST(std::string fqdn, int port, std::string uri, bool useTLS, std::string data);

#endif