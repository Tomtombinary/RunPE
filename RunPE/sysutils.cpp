#include "stdafx.h"
#include "sysutils.h"
#include <TlHelp32.h>

NtUnmapViewOfSectionFunc NtUnmapViewOfSection;

/*
* Mappe un fichier en mémoire, quelque soit le résultat c'est à l'appelant
* de fermer les handles ouvert avec unmap_file.
*
* Références :
*  - version simple https://msdn.microsoft.com/fr-fr/library/windows/desktop/aa366551(v=vs.85).aspx
*  - version ++ https://www.sysnative.com/forums/programming/21860-mapviewoffile-example-win32.html
*
* @param swFilePath : chemin vers le fichier à mapper en mémoire
* @param mFile : pointeur vers une structure de type MAPPEDFILE qui contient les handles nécessaire au mapping,
*                cette structure doit être vide
* @return TRUE si l'opération c'est bien passé
*         FALSE si l'opération c'est mal passé
*/
BOOL MapFileFromName(LPCWSTR swFilePath, PMAPPEDFILE mFile)
{
	BOOL bSuccess = FALSE;

	memset(mFile, 0, sizeof(MAPPEDFILE));

	mFile->hFile = CreateFile(swFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (mFile->hFile != INVALID_HANDLE_VALUE)
	{
		mFile->dwFileSize = GetFileSize(mFile->hFile, NULL);
		if (mFile->dwFileSize != 0)
		{
			mFile->hMapFile = CreateFileMapping(mFile->hFile, NULL, PAGE_READONLY | SEC_COMMIT, 0, mFile->dwFileSize, NULL);
			if (mFile->hMapFile != NULL)
			{
				mFile->lpView = MapViewOfFile(mFile->hMapFile, FILE_MAP_READ, 0, 0, 0);
				if (mFile->lpView != NULL)
					bSuccess = TRUE;
				else
					fprintf(stderr, "[-] MapViewOfFile\n");
			}
			else
				fprintf(stderr, "[-] Error when CreateFileMapping\n");
		}
		else
			fprintf(stderr, "[-] Can't GetFileSize\n");
	}
	else
		fprintf(stderr, "[-] Can't OpenFile\n");

	return bSuccess;
}

/*
* "Démappe" un fichier de la mémoire
* @param mFile : un pointeur vers une structure contenant les handles du fichier à "démapper"
* @return TRUE si l'opération c'est bien passée
*         FALSE s'il y a eu une erreur lors de la fermeture d'un handle
*/
BOOL UnmapFile(PMAPPEDFILE mFile)
{
	BOOL bSuccess = FALSE;
	if (mFile->lpView != NULL)
		bSuccess &= UnmapViewOfFile(mFile->lpView);
	if (mFile->hMapFile != NULL)
		bSuccess &= CloseHandle(mFile->hMapFile);
	if (mFile->hFile != NULL)
		bSuccess &= CloseHandle(mFile->hFile);
	return bSuccess;
}

/*
* Résoud les adresses des fonctions de ntdll.dll
* @return -1 si la dll n'as pas été trouvée
*/
DWORD ResolveNativeAPI()
{
	DWORD dwReturnCode = 0;
	HMODULE hModNtdll = LoadLibrary(L"ntdll.dll");
	if (hModNtdll)
	{
		NtUnmapViewOfSection = (NtUnmapViewOfSectionFunc)GetProcAddress(hModNtdll, "NtUnmapViewOfSection");
	}
	else
		dwReturnCode = -1;

	return dwReturnCode;
}