#include "stdafx.h"
#ifndef SYSUTILS_H
#define SYSUTILS_H

typedef struct _MAPPEDFILE
{
	HANDLE hFile;
	HANDLE hMapFile;
	DWORD dwFileSize;
	LPVOID lpView;
}MAPPEDFILE, *PMAPPEDFILE;

BOOL MapFileFromName(LPCWSTR szSourceExePath, PMAPPEDFILE mFile);
BOOL UnmapFile(PMAPPEDFILE mFile);

DWORD ResolveNativeAPI();

typedef LONG(WINAPI * NtUnmapViewOfSectionFunc)(HANDLE hProcess, PVOID lpBaseAddress);
extern NtUnmapViewOfSectionFunc NtUnmapViewOfSection;

#endif