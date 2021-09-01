//#pragma warning(disable : 4996)
#include <windows.h>
#define WIN32_LEAN_AND_MEAN
#include <TlHelp32.h>
#include <tchar.h>
#include <comdef.h>
#include <thread>
#define MAX_NAME 256


int GetUserFromRemoteProcess(DWORD, TCHAR*, TCHAR*);
int GetLogonFromToken(HANDLE, TCHAR*, TCHAR*);
DWORD ProcessID(const char*, TCHAR*, TCHAR*);
BOOL GetCurrentUserAndDomain(PTSTR, PDWORD, PTSTR, PDWORD);

DWORD ProcessID(const char* ProcessName, TCHAR* domain_current, TCHAR* user_current)
{
	DWORD pid;
	BOOL check = FALSE;

	//Create a snapshot of all running processes
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) return false;

	//Used to store the process info in the loop
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);

	//Get the first process
	if (Process32First(hSnapshot, &ProcEntry)) {
		do
		{
			//If the found process name is equal to the one we're searching for
			if (!strcmp(ProcEntry.szExeFile, ProcessName))
			{
				//Before passing injection on, check if value of remote process (explorer.exe) is
				//the same user that ran binary
				pid = ProcEntry.th32ProcessID;
				check = GetUserFromRemoteProcess(pid, domain_current, user_current);

				//If true and user and domain match, clean up, pass value to break loop, reeturn PID
				if (check == TRUE) {
					CloseHandle(hSnapshot);
					//Set to true to break final loop
					//Return the processID of the found process
					return ProcEntry.th32ProcessID;
				}
				//If fail, stay in loop, and keep trying
				else {
					check = FALSE;
				}
			}
		} while (Process32Next(hSnapshot, &ProcEntry) && check == FALSE); //Get the next process
	}
	CloseHandle(hSnapshot);
	//Since a process hasn't been found, return 0
	return 0;
}

BOOL GetLogonFromToken(HANDLE hToken, TCHAR* domain_current, TCHAR* user_current)
{
	DWORD dwSize = MAX_NAME;
	BOOL bSuccess;
	DWORD dwLength = 0;
	_bstr_t strUser = "";
	_bstr_t strdomain = "";
	PTOKEN_USER ptu = NULL;
	//Verify the parameter passed in is not NULL.
	if (NULL == hToken)
		goto Cleanup;

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenUser,    // get information about the token's groups 
		(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
		0,              // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			goto Cleanup;

		ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY, dwLength);

		if (ptu == NULL)
			goto Cleanup;
	}

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenUser,    // get information about the token's groups 
		(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
		dwLength,       // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		goto Cleanup;
	}
	SID_NAME_USE SidType;
	char lpName[MAX_NAME];
	char lpDomain[MAX_NAME];

	if (!LookupAccountSid(NULL, ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
	{
		DWORD dwResult = GetLastError();
		if (dwResult == ERROR_NONE_MAPPED)
			strcpy_s(lpName, "NONE_MAPPED");
		else
		{
			printf("LookupAccountSid Error %u\n", GetLastError());
		}
	}
	else
	{
		//printf("\nRemote user is  %s\\%s\n", lpDomain, lpName);
		//printf("Current user is %s\\%s\n", domain_current, user_current);
		strUser = lpName;
		strdomain = lpDomain;

		if (strcmp(strUser, user_current) == 0 && (strcmp(strdomain, domain_current) == 0)) {
			bSuccess = TRUE;
		}
		else {
			bSuccess = FALSE;
		}
	}

Cleanup:

	if (ptu != NULL)
		HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
	return bSuccess;
}
BOOL GetUserFromRemoteProcess(DWORD procId, TCHAR* domain_current, TCHAR* user_current)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
	if (hProcess == NULL)
		return E_FAIL;
	HANDLE hToken = NULL;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		CloseHandle(hProcess);
		return E_FAIL;
	}
	BOOL bres = GetLogonFromToken(hToken, domain_current, user_current);

	CloseHandle(hToken);
	CloseHandle(hProcess);
	return bres;
}
BOOL GetCurrentUserAndDomain(PTSTR szUser, PDWORD pcchUser, PTSTR szDomain, PDWORD pcchDomain) {

	BOOL         fSuccess = FALSE;
	HANDLE       hToken = NULL;
	PTOKEN_USER  ptiUser = NULL;
	DWORD        cbti = 0;
	SID_NAME_USE snu;

	__try {

		// Get the calling thread's access token.
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {

			if (GetLastError() != ERROR_NO_TOKEN)
				__leave;

			// Retry against process token if no thread token exists.
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
				__leave;
		}

		// Obtain the size of the user information in the token.
		if (GetTokenInformation(hToken, TokenUser, NULL, 0, &cbti)) {

			// Call should have failed due to zero-length buffer.
			__leave;

		}
		else {

			// Call should have failed due to zero-length buffer.
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				__leave;
		}

		// Allocate buffer for user information in the token.
		ptiUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), 0, cbti);
		if (!ptiUser)
			__leave;

		// Retrieve the user information from the token.
		if (!GetTokenInformation(hToken, TokenUser, ptiUser, cbti, &cbti))
			__leave;

		// Retrieve user name and domain name based on user's SID.
		if (!LookupAccountSid(NULL, ptiUser->User.Sid, szUser, pcchUser, szDomain, pcchDomain, &snu))
			__leave;

		fSuccess = TRUE;

	}
	__finally {

		// Free resources.
		if (hToken)
			CloseHandle(hToken);

		if (ptiUser)
			HeapFree(GetProcessHeap(), 0, ptiUser);
	}
	return fSuccess;
}
void ErrorHandling(const char* FunctionName, const char* Message = "")
{
	if (strcmp(Message, "") == 0) {
		DWORD code = GetLastError();
		exit(code);
	}
	else
	{
		exit(-1);
	}

}
BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
HMODULE GrabModule(DWORD processID, const char* strModuleName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
	// Check if the snapshot created is valid
	if (hSnapshot == INVALID_HANDLE_VALUE) return nullptr;

	MODULEENTRY32 ModEntry;
	// Call Module32First
	if (Module32First(hSnapshot, &ModEntry))
	{
		do
		{
			// Notice that you have to enable Multi-Byte character set in order
			// to avoid converting everything.
			// strcmp is not the only way to compare 2 strings ofc, work with your imagination
			if (!strcmp(ModEntry.szModule, strModuleName))
			{
				// If we are here it means that the module has been found, we can add the module to the vector
				// But first of all we have to close the snapshot handle!
				CloseHandle(hSnapshot);
				// Add ModEntry to the m_Modules vector
				return HMODULE(ModEntry.modBaseAddr);
			}
		} while (Module32Next(hSnapshot, &ModEntry));
	}
	// If we are here it means that the module has not been found or that there are no modules to scan for anymore.
	// We can close the snapshot handle and return false.
	CloseHandle(hSnapshot);
	return nullptr;
}

void GoForth() {

	char process[255] = "explorer.exe";
	char file[255] = "C:\\your\\path\\your.dll";

	//Set current process user variables
	TCHAR user_current[254], domain_current[254];
	DWORD szUser = sizeof(user_current), szDomain = sizeof(domain_current);

	//Get current user name and domain for future comparison
	GetCurrentUserAndDomain(user_current, &szUser, domain_current, &szDomain);

	//Get the ID of the process
	DWORD processID = ProcessID(process, domain_current, user_current);
	if (!processID) ErrorHandling("ProcessID", "Process ID not found");
	//Get the full path of our .dll
	char dll[MAX_PATH];
	DWORD PathNameResult = GetFullPathName(file, MAX_PATH, dll, nullptr);
	if (!PathNameResult) ErrorHandling("GetFullPathName");
	if (PathNameResult > MAX_PATH) ErrorHandling("GetFullPathName", "Path Length too short");
	if (!FileExists(dll)) ErrorHandling("FileExists", "Dll to inject does not exist");
	if (GrabModule(processID, file)) ErrorHandling("GrabModule", "Dll already injected");

	//Get a handle to the process
	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (!Process) ErrorHandling("OpenProcess");

	// Allocate space in the process for our DLL 
	LPVOID Memory = LPVOID(VirtualAllocEx(Process, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (!Memory) ErrorHandling("VirtualAllocEx");

	// Write the string name of our DLL in the memory allocated 
	if (!WriteProcessMemory(Process, Memory, dll, MAX_PATH, nullptr)) ErrorHandling("WriteProcessMemory");

	// Load our DLL
	HANDLE hThread = CreateRemoteThread(Process, nullptr, NULL, LPTHREAD_START_ROUTINE(LoadLibraryA), Memory, NULL, nullptr);
	if (!hThread) ErrorHandling("CreateRemoteThread");

	//Let the program regain control of itself.
	CloseHandle(Process);

	//Free the allocated memory.
	VirtualFreeEx(Process, LPVOID(Memory), 0, MEM_RELEASE);
}

int WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPTSTR    lpCmdLine,
	int       cmdShow) 
{
	GoForth();
	return 0;
}