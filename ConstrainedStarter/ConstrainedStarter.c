#include "pch.h"

static int Main()
{
	SAFER_LEVEL_HANDLE hAuthzLevel;
	if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_CONSTRAINED, 0, &hAuthzLevel, NULL))
	{
		return GetLastError();
	}
	HANDLE hToken;
	DWORD fStatus;
	if (!SaferComputeTokenFromLevel(
		hAuthzLevel, // SAFER Level handle
		NULL,		 // NULL is current thread token.
		&hToken,	 // Target token
		0,			 // No flags
		NULL))
	{
		fStatus = GetLastError();
		if (!SaferCloseLevel(hAuthzLevel))
		{
			return GetLastError();
		}
		return fStatus;
	}
	STARTUPINFOW si;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi;
	wchar_t* cmdl = _get_wide_winmain_command_line();
	wchar_t cmdld[] = L"cmd";
	if (CreateProcessAsUserW(hToken, NULL, cmdl[0] ? cmdl : cmdld, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		if (!CloseHandle(pi.hThread))
		{
			fStatus = GetLastError();
			if (!SaferCloseLevel(hAuthzLevel))
			{
				return GetLastError();
			}
			return fStatus;
		}
		if (!CloseHandle(pi.hProcess))
		{
			fStatus = GetLastError();
			if (!SaferCloseLevel(hAuthzLevel))
			{
				return GetLastError();
			}
			return fStatus;
		}
	}
	else
	{
		fStatus = GetLastError();
		if (!SaferCloseLevel(hAuthzLevel))
		{
			return GetLastError();
		}
		return fStatus;
	}
	if (!SaferCloseLevel(hAuthzLevel))
	{
		return GetLastError();
	}
	return 0;
}

void Startup()
{
	ExitProcess(Main());
}