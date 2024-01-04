#include "utils.h"

BOOL CheckProcessIntegrityLevel() {
    HANDLE hToken = NULL;
    DWORD dwLength = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel = 0;
    BOOL isHighIntegrity = FALSE;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            printf("[-] OpenThreadToken failed with error code: 0x%x\n", GetLastError());
            return FALSE;
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            printf("[-] OpenProcessToken failed with error code: 0x%x\n", GetLastError());
            return FALSE;
        }
    }

    // Get the size of the integrity level information
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength) && 
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("[-] GetTokenInformation failed with error code: 0x%x\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
    if (pTIL == NULL) {
        printf("[-] LocalAlloc failed with error code: 0x%x\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
        printf("[-] GetTokenInformation failed with error code: 0x%x\n", GetLastError());
        LocalFree(pTIL);
        CloseHandle(hToken);
        return FALSE;
    }

    dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        isHighIntegrity = TRUE;
    } else {
        printf("[-] This program requires to run in high integrity level.\n");
    }

    LocalFree(pTIL);
    CloseHandle(hToken);
    return isHighIntegrity;
}

// Enable SeDebugPrivilege to obtain full path of running processes
BOOL EnableSeDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPrivileges = {0};
	
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            printf("[-] OpenThreadToken failed with error code: 0x%x\n", GetLastError());
            return FALSE;
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            printf("[-] OpenProcessToken failed with error code: 0x%x\n", GetLastError());
            return FALSE;
        }
    }

	if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tokenPrivileges.Privileges[0].Luid)){
        printf("[-] LookupPrivilegeValueA failed with error code: 0x%x\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges failed with error code: 0x%x\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] Failed to get SeDebugPrivilege. You might not be able to get the process handle of the EDR process.\n");
		CloseHandle(hToken);
		return FALSE;
    }

	CloseHandle(hToken);
	return TRUE;
}

void CharArrayToWCharArray(const char charArray[], WCHAR wCharArray[], size_t wCharArraySize) {
    int result = MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wCharArray, wCharArraySize);

    if (result == 0) {
        printf("[-] MultiByteToWideChar failed with error code: 0x%x\n", GetLastError());
        wCharArray[0] = L'\0';
    }
}