#include "utils.h"

BOOL CheckProcessIntegrityLevel() {
    HANDLE hToken = NULL;
    DWORD dwLength = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel = 0;
    BOOL isHighIntegrity = FALSE;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN) {
            printf("[-] OpenThreadToken failed with error code: 0x%x.\n", GetLastError());
            return FALSE;
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            printf("[-] OpenProcessToken failed with error code: 0x%x.\n", GetLastError());
            return FALSE;
        }
    }

    // Get the size of the integrity level information
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength) && 
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("[-] GetTokenInformation failed with error code: 0x%x.\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
    if (pTIL == NULL) {
        printf("[-] LocalAlloc failed with error code: 0x%x.\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
        printf("[-] GetTokenInformation failed with error code: 0x%x.\n", GetLastError());
        LocalFree(pTIL);
        CloseHandle(hToken);
        return FALSE;
    }

    if (pTIL->Label.Sid == NULL || *GetSidSubAuthorityCount(pTIL->Label.Sid) < 1) {
        printf("[-] SID structure is invalid.\n");
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
            printf("[-] OpenThreadToken failed with error code: 0x%x.\n", GetLastError());
            return FALSE;
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            printf("[-] OpenProcessToken failed with error code: 0x%x.\n", GetLastError());
            return FALSE;
        }
    }

	if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tokenPrivileges.Privileges[0].Luid)){
        printf("[-] LookupPrivilegeValueA failed with error code: 0x%x.\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges failed with error code: 0x%x.\n", GetLastError());
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
        printf("[-] MultiByteToWideChar failed with error code: 0x%x.\n", GetLastError());
        wCharArray[0] = L'\0';
    }
}

BOOL GetDriveName(PCWSTR filePath, wchar_t* driveName, size_t driveNameSize) {
    if (!filePath) {
        return FALSE;
    }
    const wchar_t *colon = wcschr(filePath, L':');
    if (colon && (colon - filePath + 1) < driveNameSize) {
        wcsncpy(driveName, filePath, colon - filePath + 1);
        driveName[colon - filePath + 1] = L'\0';
        return TRUE;
    } else {
        return FALSE;
    }
}

ErrorCode ConvertToNtPath(PCWSTR filePath, wchar_t* ntPathBuffer, size_t bufferSize) {
    WCHAR driveName[10];
    WCHAR ntDrivePath[MAX_PATH];
    if (!filePath || !ntPathBuffer) {
        return CUSTOM_NULL_INPUT;
    }

    if (!GetDriveName(filePath, driveName, sizeof(driveName) / sizeof(WCHAR))) {
        return CUSTOM_DRIVE_NAME_NOT_FOUND;
    }

    if (QueryDosDeviceW(driveName, ntDrivePath, sizeof(ntDrivePath) / sizeof(WCHAR)) == 0) {
        return CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME;
    }

    swprintf(ntPathBuffer, bufferSize, L"%ls%ls", ntDrivePath, filePath + wcslen(driveName));
    
    for (size_t i = 0; ntPathBuffer[i] != L'\0'; ++i) {
        ntPathBuffer[i] = towlower(ntPathBuffer[i]);
    }
    return CUSTOM_SUCCESS;
}

BOOL FileExists(PCWSTR filePath) {
    if (!filePath) {
        return FALSE;
    }

    DWORD fileAttrib = GetFileAttributesW(filePath);
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    return TRUE;
}

ErrorCode CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId) {
    if (!FileExists(filePath)) {
        return CUSTOM_FILE_NOT_FOUND;
    }

    WCHAR ntPath[MAX_PATH];
    ErrorCode errorCode = ConvertToNtPath(filePath, ntPath, sizeof(ntPath));
    if (errorCode != CUSTOM_SUCCESS) {
        return errorCode;
    }
    *appId = (FWP_BYTE_BLOB*)malloc(sizeof(FWP_BYTE_BLOB));
    if (!*appId) {
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }

    (*appId)->size = wcslen(ntPath) * sizeof(WCHAR) + sizeof(WCHAR);
    
    (*appId)->data = (UINT8*)malloc((*appId)->size);
    if (!(*appId)->data) {
        free(*appId);
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }
    memcpy((*appId)->data, ntPath, (*appId)->size);
    return CUSTOM_SUCCESS;
}

void FreeAppId(FWP_BYTE_BLOB* appId) {
    if (appId) {
        if (appId->data) {
            free(appId->data);
        }
        free(appId);
    }
}

// Get provider GUID by description
BOOL GetProviderGUIDByDescription(PCWSTR providerDescription, GUID* outProviderGUID) {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    HANDLE enumHandle = NULL;
    FWPM_PROVIDER0** providers = NULL;
    UINT32 numProviders = 0;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return FALSE;
    }

    result = FwpmProviderCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmProviderCreateEnumHandle0 failed with error code: 0x%x.\n", result);
        FwpmEngineClose0(hEngine);
        return FALSE;
    }

    result = FwpmProviderEnum0(hEngine, enumHandle, 100, &providers, &numProviders);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmProviderEnum0 failed with error code: 0x%x.\n", result);
        FwpmEngineClose0(hEngine);
        return FALSE;
    }

    BOOL found = FALSE;
    for (UINT32 i = 0; i < numProviders; i++) {
        if (providers[i]->displayData.description != NULL) {
            if (wcscmp(providers[i]->displayData.description, providerDescription) == 0) {
                *outProviderGUID = providers[i]->providerKey;
                found = TRUE;
                break;
            }
        }   
    }

    if (providers) {
        FwpmFreeMemory0((void**)&providers);
    }

    FwpmProviderDestroyEnumHandle0(hEngine, enumHandle);
    FwpmEngineClose0(hEngine);
    return found;
}
