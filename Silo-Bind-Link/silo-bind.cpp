#include <windows.h>
#include <bindlink.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "bindlink.lib")

void PrintError(const std::wstring& msg, HRESULT hr) {
    std::wcerr << msg << L" Error Code: 0x" << std::hex << hr << std::dec << std::endl;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
		std::wstring exePath = argv[0];
        std::wcout << L"Usage: " << exePath << " <path_a> <path_b> [<silo_name>]\n";
        std::wcout << L"Example: " << exePath << " C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe C:\\Windows\\explorer.exe PsExp\n";
        return 1;
    }

    std::wstring pathA = argv[1];
    std::wstring pathB = argv[2];
	std::wstring siloName = L"MyTestSilo"; // Default silo name

    if (argc == 4) {
        std::wstring siloName = argv[3];
    }

	// verify pathA and pathB exist
    if (GetFileAttributesW(pathA.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"Path A does not exist: " << pathA << std::endl;
        return 1;
	}
    if (GetFileAttributesW(pathB.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"Path B does not exist: " << pathB << std::endl;
        return 1;
	}

    HRESULT hr;

    // --- 1. Create GLOBAL Bind Link: A.exe -> B.exe ---
    // Anyone on the system calling A will get B.
    hr = CreateBindLink(pathA.c_str(), pathB.c_str(), CREATE_BIND_LINK_FLAG_NONE, 0, nullptr);
    if (FAILED(hr)) {
        PrintError(L"Failed to create global bind link.", hr);
        return 1;
    }
    std::wcout << L"Global link established: " << pathA << L" -> " << pathB << std::endl;

    // --- 2. Create the Silo (Job Object) ---
    HANDLE hJob = CreateJobObjectW(nullptr, siloName.c_str());
    if (!hJob) {
        std::wcerr << L"Failed to create Job Object. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Configure Job Object to act as a Silo boundary (Simplified for Win11)
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));

    // --- 3. Create SILO-LOCAL Bind Link: B.exe -> A.exe ---
    // Inside this silo, B acts as a gateway back to A.
    // We use the Silo handle to scope this link.
    hr = CreateBindLink(pathB.c_str(), pathA.c_str(), CREATE_BIND_LINK_FLAG_NONE, 0, nullptr);
    if (FAILED(hr)) {
        PrintError(L"Failed to create silo-local bind link.", hr);
        CloseHandle(hJob);
        return 1;
    }
    std::wcout << L"Silo-local link established inside: " << siloName << std::endl;

    // --- 4. Execute PowerShell inside the Silo ---
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    std::wstring cmd = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

    // Create process in suspended state so we can attach it to the Job/Silo
    BOOL success = CreateProcessW(
        nullptr, &cmd[0], nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        nullptr, nullptr, &si, &pi
    );

    if (success) {
        AssignProcessToJobObject(hJob, pi.hProcess);
        ResumeThread(pi.hThread);

        std::wcout << L"PowerShell launched inside Silo. Waiting for exit...\n";
        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::wcerr << L"Failed to launch PowerShell. Error: " << GetLastError() << std::endl;
    }

    // Cleanup
    CloseHandle(hJob);
    return 0;
}