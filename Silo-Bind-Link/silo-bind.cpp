#include <windows.h>
#include <tlhelp32.h>
#include <bindlink.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "bindlink.lib")

bool IsParentPowerShell() {
    DWORD pid = GetCurrentProcessId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return L"";

	// Get the parent process ID
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    DWORD ppid = 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    if (ppid == 0) {
        CloseHandle(hSnapshot);
        return false;
	}

    // Get the parent process name
    std::wstring parentName = L"";
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == ppid) {
                parentName = pe32.szExeFile;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    return (parentName == L"powershell.exe");
}

// Helper to ensure paths are in the format \\?\C:\Path\To\File.exe
std::wstring NormalizePath(std::wstring path) {
    wchar_t buffer[MAX_PATH];
    GetFullPathNameW(path.c_str(), MAX_PATH, buffer, nullptr);
    std::wstring fullPath = buffer;
    if (fullPath.find(L"\\\\?\\") != 0) {
        fullPath = L"\\\\?\\" + fullPath;
    }
    return fullPath;
}

// Helper to print HRESULT errors
void CheckHr(HRESULT hr, const std::wstring& action) {
    if (FAILED(hr)) {
        std::wcerr << L"[-] " << action << L" failed. HR: 0x" << std::hex << hr << std::endl;
        exit(1);
    }
    std::wcout << L"[+] " << action << L" success." << std::endl;
}

int wmain(int argc, wchar_t* argv[]) {
    // Check if we are the "Worker" inside the Silo
    bool isWorker = (argc > 4 && std::wstring(argv[4]) == L"--inside-silo");

    if (!isWorker && argc < 4) {
        std::wstring exePath = argv[0];
        std::wcout << L"Usage: " << exePath << " <path_a> <path_b> <silo_name>\n";
        std::wcout << L"Example: " << exePath << " C:\\Windows\\SysWOW\\WindowsPowerShell\\v1.0\\PowerShell.exe C:\\Windows\\System32\\calc.exe PsCalc\n";
		std::wcout << L"Hint: Use Bind-Link-PS.exe unbind C:\\Windows\\SysWOW\\WindowsPowerShell\\v1.0\\PowerShell.exe to unbind if needed.\n";
        return 1;
    }

    std::wstring pathA = NormalizePath(argv[1]);
    std::wstring pathB = NormalizePath(argv[2]);
    std::wstring siloName = argv[3];

    // verify pathA and pathB exist
    if (GetFileAttributesW(pathA.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"Path A does not exist: " << pathA << std::endl;
        return 1;
    }
    if (GetFileAttributesW(pathB.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"Path B does not exist: " << pathB << std::endl;
        return 1;
    }

    if (!isWorker) {
        // check if powershell is bound and parent is powershell
		if (IsParentPowerShell()) {
            std::wcerr << L"[-] This tool should be run from a cmd.exe prompt to not interfere with PowerShell.exe on disk, it cannot be run from a PowerShell terminal." << std::endl;
            return 1;
		}

        // --- STAGE 1: HOST CONTEXT ---
        // 
        // 1. Global Link: A points to B (Redirection for everyone)
        // 4th/5th params fixed: 0 exceptions, nullptr path array
        std::wcout << L"[*] Global. Creating silo-local bind link " << pathA << L" -> " << pathB << L"\n";
        CheckHr(CreateBindLink(pathA.c_str(), pathB.c_str(), CREATE_BIND_LINK_FLAG_NONE, 0, nullptr),
            L"Global Bind Link (A -> B)");

        // 2. Create the Silo (Job Object)
        HANDLE hJob = CreateJobObjectW(nullptr, siloName.c_str());
        if (!hJob) return 1;

        // 3. Re-execute this tool INSIDE the Silo
        std::wstring selfPath = argv[0];
        std::wstring cmdLine = L"\"" + selfPath + L"\" \"" + pathA + L"\" \"" + pathB + L"\" \"" + siloName + L"\" --inside-silo";

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        if (CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {

            AssignProcessToJobObject(hJob, pi.hProcess);
            ResumeThread(pi.hThread);

            std::wcout << L"[*] Worker process started inside Silo. Waiting...\n";
            WaitForSingleObject(pi.hProcess, INFINITE);

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        CloseHandle(hJob);

    }
    else {
        // --- STAGE 2: INSIDE SILO CONTEXT ---
        //
        // 0. wait some time
        Sleep(1000);

        // 1. Local Link: B points to A 
        // Since this thread is inside the Job/Silo, this link is silo-local. 
		std::wcout << L"[*] Inside Silo. Creating silo-local bind link " << pathB << L" -> " << pathA << L"\n";
        CheckHr(CreateBindLink(pathB.c_str(), pathA.c_str(), CREATE_BIND_LINK_FLAG_NONE, 0, nullptr),
            L"Silo-Local Bind Link (B -> A)");

        // 2. Launch PowerShell
        std::wstring psPath = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

		std::wcout << L"[*] Launching " << psPath << L" inside Silo...\n";
        if (CreateProcessW(nullptr, &psPath[0], nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
            std::wcout << L"[*] PowerShell active in Silo. " << pathB << " now resolves to " << pathA << " here.\n";
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            // TODO: this does not launch in the silo
        }
        /*
        Sleep(10000);
        std::wcout << L"[*] PowerShell exited. Cleaning up bind links...\n";

        std::wstring unbindA = L"\"C:\\Users\\hacker\\source\\repos\\Decondition-Enumerator\\x64\\Release\\Bind-Link-PS.exe unbind" + pathA;
        CreateProcessW(nullptr, &unbindA[0], nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
        std::wstring unbindB = L"\"C:\\Users\\hacker\\source\\repos\\Decondition-Enumerator\\x64\\Release\\Bind-Link-PS.exe unbind" + pathB;
        CreateProcessW(nullptr, &unbindB[0], nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
        */
    }

    return 0;
}