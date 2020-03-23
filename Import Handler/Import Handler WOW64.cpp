#ifdef _WIN64

#include "Import Handler.h"

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

HINSTANCE GetModuleHandleEx_WOW64(HANDLE hTargetProc, const TCHAR * szModuleName)
{
#ifdef UNICODE
	return GetModuleHandleExW_WOW64(hTargetProc, szModuleName);
#else
	return GetModuleHandleExA_WOW64(hTargetProc, szModuleName);
#endif
}

HINSTANCE GetModuleHandleExA_WOW64(HANDLE hTargetProc, const char * lpModuleName)
{
	MODULEENTRY32 ME32{ 0 };
	ME32.dwSize = sizeof(ME32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		while (GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetProcessId(hTargetProc));

			if (hSnap != INVALID_HANDLE_VALUE)
			{
				break;
			}
		}
	}

	if (hSnap == INVALID_HANDLE_VALUE || !hSnap)
	{
		return NULL;
	}

	BOOL bRet = Module32First(hSnap, &ME32);
	do
	{
		if (!_stricmp(ME32.szModule, lpModuleName) && (ME32.modBaseAddr < (BYTE *)0x7FFFF000))
		{
			break;
		}

		bRet = Module32Next(hSnap, &ME32);
	} while (bRet);

	CloseHandle(hSnap);

	if (!bRet)
	{
		return NULL;
	}

	return ME32.hModule;
}

HINSTANCE GetModuleHandleExW_WOW64(HANDLE hTargetProc, const wchar_t * lpModuleName)
{
	MODULEENTRY32W ME32{ 0 };
	ME32.dwSize = sizeof(ME32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		while (GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetProcessId(hTargetProc));

			if (hSnap != INVALID_HANDLE_VALUE)
			{
				break;
			}
		}
	}

	if (hSnap == INVALID_HANDLE_VALUE || !hSnap)
	{
		return NULL;
	}

	BOOL bRet = Module32FirstW(hSnap, &ME32);
	do
	{
		if (!_wcsicmp(ME32.szModule, lpModuleName) && (ME32.modBaseAddr < (BYTE *)0x7FFFF000))
		{
			break;
		}

		bRet = Module32NextW(hSnap, &ME32);
	} while (bRet);

	CloseHandle(hSnap);

	if (!bRet)
	{
		return NULL;
	}

	return ME32.hModule;
}

bool GetProcAddressEx_WOW64(HANDLE hTargetProc, HINSTANCE hModule, const char * szProcName, void * &pOut)
{
	BYTE * modBase = reinterpret_cast<BYTE*>(hModule);

	if (!modBase)
	{
		return false;
	}

	BYTE * pe_header = new BYTE[0x1000];
	if (!pe_header)
	{
		return false;
	}

	BYTE * pBuffer = new BYTE[0x1000];
	if (!ReadProcessMemory(hTargetProc, modBase, pBuffer, 0x1000, nullptr))
	{
		delete[] pBuffer;

		return false;
	}

	auto * pNT = reinterpret_cast<IMAGE_NT_HEADERS32*>(reinterpret_cast<IMAGE_DOS_HEADER*>(pBuffer)->e_lfanew + pBuffer);
	auto * pDir = &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	auto ExportSize = pDir->Size;
	auto DirRVA		= pDir->VirtualAddress;

	if (!ExportSize)
	{
		delete[] pBuffer;

		return false;
	}

	BYTE * pExpDirBuffer = new BYTE[ExportSize];
	auto * pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pExpDirBuffer);
	if (!ReadProcessMemory(hTargetProc, modBase + DirRVA, pExpDirBuffer, ExportSize, nullptr))
	{
		delete[] pExpDirBuffer;
		delete[] pBuffer;

		return false;
	}

	BYTE * pBase = pExpDirBuffer - DirRVA;

	auto Forward = [&](DWORD FuncRVA, void * &pForwarded) -> bool
	{
		char pFullExport[MAX_PATH]{ 0 };
		size_t len_out = strlen(reinterpret_cast<char *>(pBase + FuncRVA));
		memcpy(pFullExport, reinterpret_cast<char *>(pBase + FuncRVA), len_out);
		
		char * pFuncName = strchr(pFullExport, '.');
		*pFuncName++ = '\0';
		if (*pFuncName == '#')
		{
			pFuncName = reinterpret_cast<char *>(LOWORD(atoi(++pFuncName)));
		}


		HINSTANCE hForwardDll = GetModuleHandleExA_WOW64(hTargetProc, pFullExport);

		if (hForwardDll)
		{
			return GetProcAddressEx_WOW64(hTargetProc, hForwardDll, pFuncName, pOut);
		}

		return false;
	};

	if (reinterpret_cast<ULONG_PTR>(szProcName) <= MAXWORD)
	{
		WORD Base		= LOWORD(pExportDir->Base - 1);
		WORD Ordinal	= LOWORD(szProcName) - Base;
		DWORD FuncRVA	= reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

		delete[] pExpDirBuffer;
		delete[] pBuffer;

		if (FuncRVA >= DirRVA && FuncRVA < DirRVA + ExportSize)
		{
			return Forward(FuncRVA, pOut);
		}
			
		pOut = modBase + FuncRVA;
		
		return true;
	}

	DWORD max		= pExportDir->NumberOfNames - 1;
	DWORD min		= 0;
	DWORD FuncRVA	= 0;

	while (min <= max)
	{
		DWORD mid = (min + max) / 2;

		DWORD CurrNameRVA	= reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfNames)[mid];
		char * szName		= reinterpret_cast<char*>(pBase + CurrNameRVA);

		int cmp = strcmp(szName, szProcName);
		if (cmp < 0)
		{
			min = mid + 1;
		}
		else if (cmp > 0)
		{
			max = mid - 1;
		}
		else 
		{
			WORD Ordinal = reinterpret_cast<WORD*>(pBase + pExportDir->AddressOfNameOrdinals)[mid];
			FuncRVA = reinterpret_cast<DWORD *>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

			break;
		}
	}
	
	delete[] pExpDirBuffer;
	delete[] pBuffer;

	if (!FuncRVA)
	{
		return false;
	}

	if (FuncRVA >= DirRVA && FuncRVA < DirRVA + ExportSize)
	{
		return Forward(FuncRVA, pOut);
	}

	pOut = modBase + FuncRVA;

	return true;
}

#endif