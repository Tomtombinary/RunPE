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

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS(WINAPI * NtUnmapViewOfSectionFunc)
(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
);

typedef NTSTATUS(WINAPI * NtMapViewOfSectionFunc)
(
	_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID           *BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        SECTION_INHERIT InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect
);

typedef NTSTATUS(WINAPI* NtCreateSectionFunc)
(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
);

extern NtUnmapViewOfSectionFunc NtUnmapViewOfSection;
extern NtMapViewOfSectionFunc NtMapViewOfSection;
extern NtCreateSectionFunc NtCreateSection;

#endif