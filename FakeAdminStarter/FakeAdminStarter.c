
#include "pch.h"

HANDLE hCurrentProcess;
HANDLE hProcessHeap;
DWORD dwLastError;
// Custom memory management functions using process heap
#define Malloc(size) HeapAlloc(hProcessHeap, 0, size)
#define Realloc(ptr, size) HeapReAlloc(hProcessHeap, 0, ptr, size)
#define Free(ptr) HeapFree(hProcessHeap, 0, ptr)

// Function to handle limited token elevation by running as administrator
DWORD HandleLimitedToken(LPWSTR lpCmdLine)
{
	DWORD dwSize = MAX_PATH;
	LPWSTR lpExeName = Malloc(dwSize * sizeof(wchar_t));
	if (!lpExeName)
	{
		return ERROR_OUTOFMEMORY;
	}

	while (!QueryFullProcessImageNameW(hCurrentProcess, 0, lpExeName, &dwSize))
	{
		dwLastError = GetLastError();
		if (dwLastError != ERROR_INSUFFICIENT_BUFFER)
		{
			Free(lpExeName);
			return dwLastError;
		}
		dwSize *= 2;
		LPWSTR temp = Realloc(lpExeName, dwSize * sizeof(wchar_t));
		if (!temp)
		{
			Free(lpExeName);
			return ERROR_OUTOFMEMORY;
		}
		lpExeName = temp;
	}

	INT_PTR nResult = (INT_PTR)ShellExecuteW(0, L"runas", lpExeName, lpCmdLine, 0, SW_SHOW);
	Free(lpExeName);
	if (nResult <= 32)
	{
		return (DWORD)nResult;  // ShellExecuteW returns error code directly, not via GetLastError
	}
	return ERROR_SUCCESS;
}

// Function to handle full token elevation by creating restricted process
DWORD HandleFullToken(HANDLE hToken, LPWSTR lpCmdLine)
{
	if (!CreateRestrictedToken(hToken, LUA_TOKEN, 0, 0, 0, 0, 0, 0, &hToken))
	{
		return GetLastError();
	}

	TOKEN_LINKED_TOKEN linkedTokenInfo;
	DWORD dwReturnLength;
	BOOL bHasLinkedToken = TRUE;
	if (!GetTokenInformation(hToken, TokenLinkedToken, &linkedTokenInfo, sizeof(TOKEN_LINKED_TOKEN), &dwReturnLength))
	{
		dwLastError = GetLastError();
		if (dwLastError == ERROR_NO_SUCH_LOGON_SESSION)
		{
			bHasLinkedToken = FALSE;
		}
		else
		{
			if (!CloseHandle(hToken))
			{
				return GetLastError();
			}
			return dwLastError;
		}
	}

	if (bHasLinkedToken)
	{
		// Get integrity level from linked token
		DWORD dwTILSize = 0;
		GetTokenInformation(linkedTokenInfo.LinkedToken, TokenIntegrityLevel, NULL, 0, &dwTILSize);
		TOKEN_MANDATORY_LABEL *pTIL = Malloc(dwTILSize);
		if (!pTIL)
		{
			if(!CloseHandle(hToken))
			{
				return GetLastError();
			}
			return ERROR_OUTOFMEMORY;
		}
		if (!GetTokenInformation(linkedTokenInfo.LinkedToken, TokenIntegrityLevel, pTIL, dwTILSize, &dwTILSize))
		{
			dwLastError = GetLastError();
			Free(pTIL);
			if (!CloseHandle(hToken))
			{
				return GetLastError();
			}
			return dwLastError;
		}

		// Get default DACL from linked token
		DWORD dwDaclSize = 0;
		GetTokenInformation(linkedTokenInfo.LinkedToken, TokenDefaultDacl, NULL, 0, &dwDaclSize);
		TOKEN_DEFAULT_DACL *pDacl = Malloc(dwDaclSize);
		if (!pDacl)
		{
			Free(pTIL);
			if(!CloseHandle(hToken))
			{
				return GetLastError();
			}
			return ERROR_OUTOFMEMORY;
		}
		if (!GetTokenInformation(linkedTokenInfo.LinkedToken, TokenDefaultDacl, pDacl, dwDaclSize, &dwDaclSize))
		{
			dwLastError = GetLastError();
			Free(pTIL);
			Free(pDacl);
			if (!CloseHandle(hToken))
			{
				return GetLastError();
			}
			return dwLastError;
		}

		// Set integrity level and DACL on restricted token
		if (!SetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwTILSize) ||
			!SetTokenInformation(hToken, TokenDefaultDacl, pDacl, dwDaclSize))
		{
			dwLastError = GetLastError();
			Free(pTIL);
			Free(pDacl);
			if (!CloseHandle(hToken))
			{
				return GetLastError();
			}
			return dwLastError;
		}
		Free(pTIL);
		Free(pDacl);
	}
	else
	{
		// Set medium integrity level
		PSID pMediumIntegrityLevel;
		if (!ConvertStringSidToSidW(L"S-1-16-0x2000", &pMediumIntegrityLevel))
		{
			dwLastError = GetLastError();
			if (!CloseHandle(hToken))
			{
				return GetLastError();
			}
			return dwLastError;
		}
		if (!SetTokenInformation(hToken, TokenIntegrityLevel, &(TOKEN_MANDATORY_LABEL){{pMediumIntegrityLevel, SE_GROUP_INTEGRITY}}, sizeof(TOKEN_MANDATORY_LABEL)))
		{
			dwLastError = GetLastError();
			FreeSid(pMediumIntegrityLevel);
			if (!CloseHandle(hToken))
			{
				return GetLastError();
			}
			return dwLastError;
		}
		FreeSid(pMediumIntegrityLevel);
	}

	// Create process with restricted token
	wchar_t szCmdDefault[] = L"cmd";
	PROCESS_INFORMATION piProcInfo;
	if (!CreateProcessAsUserW(hToken, 0, lpCmdLine[0] ? lpCmdLine : szCmdDefault, 0, 0, 0, 0, 0, 0, &(STARTUPINFOW){sizeof(STARTUPINFOW)}, &piProcInfo))
	{
		dwLastError = GetLastError();
		if (!CloseHandle(hToken))
		{
			return GetLastError();
		}
		return dwLastError;
	}
	if(!CloseHandle(piProcInfo.hThread))
	{
		return GetLastError();
	}
	if(!CloseHandle(piProcInfo.hProcess))
	{
		return GetLastError();
	}
	if(!CloseHandle(hToken))
	{
		return GetLastError();
	}
	return ERROR_SUCCESS;
}

#ifndef _DEBUG
static int Main(LPWSTR lpCmdLine)
#else
int
	WINAPI
	wWinMain(
		_In_ HINSTANCE hInstance,
		_In_opt_ HINSTANCE hPrevInstance,
		_In_ LPWSTR lpCmdLine,
		_In_ int nShowCmd)
#endif
{
	hProcessHeap = GetProcessHeap();
	hCurrentProcess = GetCurrentProcess();
	HANDLE hToken;
	if (!OpenProcessToken(hCurrentProcess, TOKEN_ALL_ACCESS, &hToken))
	{
		return GetLastError();
	}

	TOKEN_ELEVATION_TYPE eElevationType;
	DWORD dwReturnLength;
	if (!GetTokenInformation(hToken, TokenElevationType, &eElevationType, sizeof(TOKEN_ELEVATION_TYPE), &dwReturnLength))
	{
		dwLastError = GetLastError();
		if (!CloseHandle(hToken))
		{
			return GetLastError();
		}
		return dwLastError;
	}

	DWORD dwResult;
	switch (eElevationType)
	{
	case TokenElevationTypeDefault:
		dwResult = ERROR_NOT_SUPPORTED;
		break;
	case TokenElevationTypeLimited:
		dwResult = HandleLimitedToken(lpCmdLine);
		break;
	case TokenElevationTypeFull:
		dwResult = HandleFullToken(hToken, lpCmdLine);
		break;
	default:
		dwResult = ERROR_NOT_SUPPORTED;
		break;
	}
	if (!CloseHandle(hToken))
	{
		return GetLastError();
	}
	return dwResult;
}

#ifndef _DEBUG
void Startup()
{
	//LPWSTR cmdLine = GetCommandLineW();
	//LPWSTR lpCmdLine = cmdLine;
	//if (*lpCmdLine == L'"')
	//{
	//	lpCmdLine++;
	//	while (*lpCmdLine && *lpCmdLine != L'"')
	//		lpCmdLine++;
	//	if (*lpCmdLine)
	//		lpCmdLine++;
	//}
	//else
	//{
	//	while (*lpCmdLine && *lpCmdLine != L' ')
	//		lpCmdLine++;
	//}
	//while (*lpCmdLine == L' ')
	//	lpCmdLine++;
	ExitProcess(Main(_get_wide_winmain_command_line()));
}
#endif
