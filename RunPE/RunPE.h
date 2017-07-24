#include "stdafx.h"
#include "sysutils.h"

#ifndef RUNPE_H
#define RUNPE_H

#define RUNPE_FAILED -1

DWORD CreateProcessAndInjectPE(LPCWSTR szTargetExePath, LPCWSTR szSourceExePath);
DWORD InjectPE(LPPROCESS_INFORMATION lpProcessInfo, PVOID pBuffer, DWORD dwSizeOfBuffer);

#endif