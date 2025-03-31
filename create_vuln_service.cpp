// c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
// cl.exe /EHsc /nologo /Ox /MT /W0 /GS- /DNDDEBUG /TP create_service.cpp /link /OUT:create_service.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

#include <windows.h>
#include <iostream>
#include <string>
#include <sddl.h>

#pragma comment(lib,"advapi32.lib")

DWORD CreateServiceWithSecurity(
    SC_HANDLE schSCManager,
    LPCWSTR lpServiceName,
    LPCWSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPCWSTR lpBinaryPathName,
    LPCWSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPCWSTR lpDependencies,
    LPCWSTR lpServiceStartName,
    LPCWSTR lpPassword,
    LPCWSTR lpSDDL
) {
    DWORD dwError = ERROR_SUCCESS;
    SC_HANDLE schService = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    // Convert SDDL to security descriptor
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        lpSDDL,
        SDDL_REVISION_1,
        &pSD,
        NULL
    )) {
        dwError = GetLastError();
        std::cout << L"Failed to convert SDDL to Security Descriptor. Error: " << dwError << std::endl;
        goto Cleanup;
    }

    // Create the service with the specified security descriptor
    schService = CreateServiceW(
        schSCManager,
        lpServiceName,
        lpDisplayName,
        dwDesiredAccess,
        dwServiceType,
        dwStartType,
        dwErrorControl,
        lpBinaryPathName,
        lpLoadOrderGroup,
        lpdwTagId,
        lpDependencies,
        lpServiceStartName,
        lpPassword
    );

    if (schService == NULL) {
        dwError = GetLastError();
        std::wcerr << L"Failed to create service. Error: " << dwError << std::endl;
    } else {
        // Set the security descriptor for the service
        if (!SetServiceObjectSecurity(schService, DACL_SECURITY_INFORMATION, pSD)) {
            dwError = GetLastError();
            std::wcerr << L"Failed to set security descriptor for service. Error: " << dwError << std::endl;
        } else {
            std::wcout << L"Service created and security descriptor set successfully." << std::endl;
        }
        CloseServiceHandle(schService);
    }

Cleanup:
    if (pSD) {
        LocalFree(pSD);
    }
    return dwError;
}

int main() {
    SC_HANDLE schSCManager = NULL;
    DWORD dwError = ERROR_SUCCESS;

    // Open the Service Control Manager
    schSCManager = OpenSCManagerW(
        NULL,                    // local computer
        NULL,                    // ServicesActive database 
        SC_MANAGER_CREATE_SERVICE // full access rights 
    );

    if (schSCManager == NULL) {
        dwError = GetLastError();
        std::wcerr << L"Failed to open Service Manager. Error: " << dwError << std::endl;
        return dwError;
    }

    // Parameters for the service (you need to specify these)
    LPCWSTR lpServiceName = L"TEST";
    LPCWSTR lpDisplayName = L"TEST";
    LPCWSTR lpBinaryPathName = L"C:\\Users\\Public\\server.exe"; // Adjust this path
	LPCWSTR lpSDDL = L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CC;;;AU)";
	
	
    //LPCWSTR lpSDDL = L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";
	
	//LPCWSTR lpSDDL = L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)";
    // Create the service
    dwError = CreateServiceWithSecurity(
        schSCManager,
        lpServiceName,
        lpDisplayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        lpBinaryPathName,
        NULL,  // Load order group
        NULL,  // Tag ID
        NULL,  // Dependencies
        NULL,  // Service start name
        NULL,  // Password
        lpSDDL
    );

    // Close the handle to the service control manager database
    CloseServiceHandle(schSCManager);

    if (dwError == ERROR_SUCCESS) {
        std::wcout << L"Service creation completed successfully." << std::endl;
    } else {
        std::wcerr << L"Service creation failed with error: " << dwError << std::endl;
    }

    return dwError;
}