#pragma once
#ifndef PARSERCREATEPROCESS_H
#define PARSERCREATEPROCESS_H

#include <windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <winhttp.h>
#include <tuple>
#include <algorithm>

int runProcessCustom(std::string job_id_in, std::string agent_id_in, std::string command_in, std::string status_in, std::string args_in);

#endif