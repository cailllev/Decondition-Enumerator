#include <windows.h>
#include <bindlink.h>
#include <iostream>

#pragma comment(lib, "Bindlink.lib")
/*
* executes the shadowed exe, then points shadowed exe to backing exe with a bind link, see https://insomnihack.ch/talks/silo-binding-uncovering-the-ghost-in-the-silo/
*/
int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        std::wcout << L"Usage: BindExecutor.exe <Backing Exe> <Shadowed Exe>" << std::endl;
        std::wcout << L"Example: BindTool.exe C:\\Windows\\System32\\calc.exe C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe" << std::endl;
        return 1;
    }

    wchar_t* backingExePath = argv[1];  // the backing path
    wchar_t* shadowedExePath = argv[2]; // redirected to backing exe (after initial execution)

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(shadowedExePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::wcerr << L"Failed to execute " << shadowedExePath << L". Code: " << GetLastError() << std::endl;
        return 1;
    }
    std::wcout << L"Successfully executed the (to be) Shadowed executable!" << std::endl;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    HRESULT hr = CreateBindLink(
        aliasPath,      // Virtual Path (The Shadow)
        realExePath,    // Backing Path (The Real Code)
        CREATE_BIND_LINK_FLAG_NONE,
        0, NULL
    );
    if (FAILED(hr)) {
        std::wcerr << L"CreateBindLink failed: 0x" << std::hex << hr << std::endl;
        return 1;
    }

    std::wcout << L"Success: " << aliasPath << L" now points to " << realExePath << std::endl;

    return 0;
}
