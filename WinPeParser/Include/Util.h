#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <algorithm>
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include "Logger.h"

bool GetExecPathFromPID(DWORD pid, std::string& exePath);
bool IsNumber(const std::string& s);
bool isUserAnAdmin();
bool relaunchAsAdmin();
#endif // UTIL_H
