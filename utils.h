#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <stdio.h>
#include <tlhelp32.h>

#define FWPM_FILTER_FLAG_PERSISTENT (0x00000001)
BOOL CheckProcessIntegrityLevel();
BOOL EnableSeDebugPrivilege();
void CharArrayToWCharArray(const char charArray[], WCHAR wCharArray[], size_t wCharArraySize);