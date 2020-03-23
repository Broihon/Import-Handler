#include "Import Handler.h"

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#undef GetModuleHandleEx
#endif

HINSTANCE GetModuleHandleEx(HANDLE hTargetProc, const TCHAR * szModuleName)
{
#ifdef UNICODE
	return GetModuleHandleExW(hTargetProc, szModuleName);
#else
	return GetModuleHandleExA(hTargetProc, szModuleName);
#endif
}

HINSTANCE GetModuleHandleExA(HANDLE hTargetProc, const char * szModuleName)
{
	MODULEENTRY32 ME32{ 0 };
	ME32.dwSize = sizeof(ME32);
	
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		while (GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
		
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
		if (!_stricmp(ME32.szModule, szModuleName))
		{
			break;
		}

		bRet = Module32Next(hSnap, &ME32);
	} 
	while (bRet);
	
	CloseHandle(hSnap);

	if (!bRet)
	{
		return NULL;
	}

	return ME32.hModule;
}

HINSTANCE GetModuleHandleExW(HANDLE hTargetProc, const wchar_t * szModuleName)
{
	MODULEENTRY32W ME32{ 0 };
	ME32.dwSize = sizeof(ME32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		while (GetLastError() == ERROR_BAD_LENGTH)
		{
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hTargetProc));

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
		if (!_wcsicmp(ME32.szModule, szModuleName))
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

bool GetProcAddressEx(HANDLE hTargetProc, HINSTANCE hModule, const char * szProcName, void * &pOut)
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

	if (!ReadProcessMemory(hTargetProc, modBase, pe_header, 0x1000, nullptr))
	{
		delete[] pe_header;

		return false;
	}

	auto * pNT			= reinterpret_cast<IMAGE_NT_HEADERS*>(pe_header + reinterpret_cast<IMAGE_DOS_HEADER*>(pe_header)->e_lfanew);
	auto * pExportEntry	= &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	auto ExportSize		= pExportEntry->Size;
	auto ExportDirRVA	= pExportEntry->VirtualAddress;
	
	if (!ExportSize)
	{
		delete[] pe_header;

		return false;
	}

	BYTE * export_data = new BYTE[ExportSize];
	if (!export_data)
	{
		delete[] pe_header;

		return false;
	}

	if (!ReadProcessMemory(hTargetProc, modBase + ExportDirRVA, export_data, ExportSize, nullptr))
	{
		delete[] export_data;
		delete[] pe_header;

		return false;
	}
		
	BYTE * localBase	= export_data - ExportDirRVA;
	auto pExportDir		= reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(export_data);

	auto Forward = [&](DWORD FuncRVA) -> bool
	{
		char pFullExport[MAX_PATH]{ 0 };
		size_t len_out = strlen(reinterpret_cast<char*>(localBase + FuncRVA));
		memcpy(pFullExport, reinterpret_cast<char*>(localBase + FuncRVA), len_out);

		char * pFuncName = strchr(pFullExport, '.');
		*(pFuncName++) = '\0';
		if (*pFuncName == '#')
		{
			pFuncName = reinterpret_cast<char *>(LOWORD(atoi(++pFuncName)));
		}

		HINSTANCE hForwardDll = GetModuleHandleExA(hTargetProc, pFullExport);

		if (hForwardDll)
		{
			return GetProcAddressEx(hTargetProc, hForwardDll, pFuncName, pOut);
		}

		return false;
	};

	if ((reinterpret_cast<ULONG_PTR>(szProcName) & 0xFFFFFF) <= MAXWORD)
	{
		WORD Base		= LOWORD(pExportDir->Base - 1);
		WORD Ordinal	= LOWORD(szProcName) - Base;
		DWORD FuncRVA	= reinterpret_cast<DWORD*>(localBase + pExportDir->AddressOfFunctions)[Ordinal];
		
		delete[] export_data;
		delete[] pe_header;

		if (FuncRVA >= ExportDirRVA && FuncRVA < ExportDirRVA + ExportSize)
		{
			return Forward(FuncRVA);
		}

		return modBase + FuncRVA;
	}

	DWORD max		= pExportDir->NumberOfNames - 1;
	DWORD min		= 0;
	DWORD FuncRVA	= 0;

	while (min <= max)
	{
		DWORD mid = (min + max) / 2;

		DWORD CurrNameRVA	= reinterpret_cast<DWORD*>(localBase + pExportDir->AddressOfNames)[mid];
		char * szName		= reinterpret_cast<char*>(localBase + CurrNameRVA);

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
			WORD Ordinal = reinterpret_cast<WORD*>(localBase + pExportDir->AddressOfNameOrdinals)[mid];
			FuncRVA = reinterpret_cast<DWORD*>(localBase + pExportDir->AddressOfFunctions)[Ordinal];

			break;
		}
	}

	delete[] export_data;
	delete[] pe_header;

	if (!FuncRVA)
	{
		return false;
	}
	
	if (FuncRVA >= ExportDirRVA && FuncRVA < ExportDirRVA + ExportSize)
	{
		return Forward(FuncRVA);
	}
	
	pOut = modBase + FuncRVA;

	return true;
}