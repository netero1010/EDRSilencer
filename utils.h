#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <stdio.h>
#include <tlhelp32.h>

// d78e1e87-8644-4ea5-9437-d809ecefc971
DEFINE_GUID(
   FWPM_CONDITION_ALE_APP_ID,
   0xd78e1e87,
   0x8644,
   0x4ea5,
   0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71
);

// c38d57d1-05a7-4c33-904f-7fbceee60e82
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V4,
   0xc38d57d1,
   0x05a7,
   0x4c33,
   0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
);

// 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V6,
   0x4a72393b,
   0x319f,
   0x44bc,
   0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4
);

typedef enum ErrorCode {
    CUSTOM_SUCCESS = 0,
    CUSTOM_FILE_NOT_FOUND = 0x1,
    CUSTOM_MEMORY_ALLOCATION_ERROR = 0x2,
    CUSTOM_NULL_INPUT = 0x3,
    CUSTOM_DRIVE_NAME_NOT_FOUND = 0x4,
    CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME = 0x5,
} ErrorCode;

#define FWPM_FILTER_FLAG_PERSISTENT (0x00000001)
#define FWPM_PROVIDER_FLAG_PERSISTENT (0x00000001)
BOOL CheckProcessIntegrityLevel();
BOOL EnableSeDebugPrivilege();
void CharArrayToWCharArray(const char charArray[], WCHAR wCharArray[], size_t wCharArraySize);
BOOL GetDriveName(PCWSTR fileName, wchar_t* driveName, size_t driveNameSize);
ErrorCode ConvertToNtPath(PCWSTR filePath, wchar_t* ntPathBuffer, size_t bufferSize);
BOOL FileExists(PCWSTR filePath);
ErrorCode CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId);
void FreeAppId(FWP_BYTE_BLOB* appId);
BOOL GetProviderGUIDByDescription(PCWSTR providerDescription, GUID* outProviderGUID);