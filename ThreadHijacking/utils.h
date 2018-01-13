#pragma once
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

//code from nico's book
DWORD GetProcessThreadID(HANDLE Process);
void threadHijacking(HANDLE proc, const wchar_t* dllPath);