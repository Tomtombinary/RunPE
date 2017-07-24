// RunPE.cpp : définit le point d'entrée pour l'application console.
//

/*
 * Utilitaire pour lancer un processus dans un autre
 * @author : Tomtombinary
 */

#include "stdafx.h"

#include "RunPE.h"
#include "sysutils.h"

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD dwReturnCode = 0;
	if (argc > 2)
	{
		ResolveNativeAPI();
		dwReturnCode = CreateProcessAndInjectPE(argv[1], argv[2]);
	}
	else
	{
		wprintf(L"==== RunPE utility tools ====\n");
		wprintf(L"Author: Tomtombinary");
		wprintf(L"Usage : %ws <TargetExe> <ImageExe>\n", argv[0]);
	}

	return dwReturnCode;
}

/*
 * 
 * Créer un processus et remplace l'image de celui-ci par celle du paramètre SourceExePath
 * @param TargetExePath : chemin de l'executable à lancer puis à remplacer
 * @param SourceExePath : chemin de l'executable à injecter dans la cible
 * @return 0 si l'injection échoue
 *         1 si l'injection réussie
 */
DWORD CreateProcessAndInjectPE(LPCWSTR TargetExePath, LPCWSTR SourceExePath)
{
	DWORD dwReturnCode = 0;
	STARTUPINFOW SI;
	PROCESS_INFORMATION PI;
	MAPPEDFILE mFile;

	/* 
	 * Création du processus en suspend
	 * thread en suspend sur RtlUserThreadStart
	 */
	ZeroMemory(&PI, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&SI, sizeof(STARTUPINFOW));
	if (!CreateProcessW(TargetExePath, NULL, 0, 0, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 0, 0, &SI, &PI))
	{
		fprintf(stderr, "[-] CreateProcessW failed\n");
		return RUNPE_FAILED;
	}

	/* Mapping du fichier en mémoire */
	if (MapFileFromName(SourceExePath, &mFile))
	{
		/* Injection du fichier dans le processus */
		dwReturnCode = InjectPE(&PI, mFile.lpView, mFile.dwFileSize);
	}
	else
		fprintf(stderr, "[-] MapFileFromName failed\n");
	/* Demapping du fichier en mémoire */
	UnmapFile(&mFile);
	return dwReturnCode;
}


/*
* 
* Remplace l'image d'un processus par une autre
* @param pProcessInfo : pointeur vers une structure qui contient les informations du processus
* @param Buffer : pointeur vers la nouvelle image du processus
* @param SizeOfBuffer : taille de la nouvelle image
* @return 0 si l'injection échoue
*         1 si l'injection réussie
*
*/
DWORD InjectPE(LPPROCESS_INFORMATION pProcessInfo, PVOID Buffer, DWORD SizeOfBuffer)
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
		return RUNPE_FAILED;
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
		return RUNPE_FAILED;
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
		return RUNPE_FAILED;
	}


	/* Realloue de la mémoire pour la nouvelle image du processus */
	LPVOID pImageBase = VirtualAllocEx(
		pProcessInfo->hProcess,
		Peb.Reserved3[1],
		INH->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
		); 

	printf("ImageBase : %p\n", pImageBase);
	if (pImageBase)
	{
		if (WriteProcessMemory(
			pProcessInfo->hProcess,
			pImageBase,
			Buffer,
			INH->OptionalHeader.SizeOfHeaders, NULL))
		{
			// Remappe chaque sections au bon endroit
			// ImageBase + RVA de la section
			for (int i = 0; i < INH->FileHeader.NumberOfSections; i++)
			{
				PIMAGE_SECTION_HEADER ISH = PIMAGE_SECTION_HEADER(DWORD(Buffer) + IDH->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (i * sizeof(IMAGE_SECTION_HEADER)));

				printf("Section %s : \n", ISH->Name);
				printf("\t- Virtual Address : 0x%x\n", ISH->VirtualAddress);
				printf("\t- Raw Size : %d\n", ISH->SizeOfRawData);
				printf("\t- Pointer to Raw Data : 0x%x\n", ISH->PointerToRawData);
				printf("\t- Characteristics : %x\n", ISH->Characteristics);

				bSucess = WriteProcessMemory
					(
					pProcessInfo->hProcess,
					LPVOID((DWORD)pImageBase + ISH->VirtualAddress),
					LPVOID((DWORD)Buffer + ISH->PointerToRawData),
					ISH->SizeOfRawData,
					NULL
					);

				/* Applique les caractéristiques */
				bSucess = VirtualProtectEx(pProcessInfo->hProcess, (LPVOID)((DWORD)pImageBase + ISH->VirtualAddress), ISH->Misc.VirtualSize, ISH->Characteristics & 0xFFF,&dwOldProtect);
			}

			// On met à jour le Process Environement Block
			bSucess = WriteProcessMemory(pProcessInfo->hProcess, LPVOID(Context.Ebx + FIELD_OFFSET(PEB, Reserved3[1])), LPVOID(&pImageBase), sizeof(LPVOID), NULL);
			if (!bSucess)
			{
				fprintf(stderr, "[-] WriteProcessMemory failed\n");
				return RUNPE_FAILED;
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
				return RUNPE_FAILED;
			}

			/* Reprise du thread principal */
			ResumeThread(pProcessInfo->hThread);
		}
	}
	return 0;
}
