#include <windows.h>
#include <bindlink.h>
#include <iostream>

void usage(wchar_t* currentExePath) {
    std::wcout << L"Usage: " << currentExePath << " bind <Backing Exe> <Shadowed Exe>" << std::endl;
    std::wcout << L"Usage: " << currentExePath << " unbind <Shadowed Exe>" << std::endl;
    std::wcout << L"Example: " << currentExePath << " bind C:\\Windows\\System32\\calc.exe C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe" << std::endl;
    std::wcout << L"Example: " << currentExePath << " bind-exec C:\\Windows\\System32\\calc.exe C:\\Temp\\my.exe" << std::endl;
    std::wcout << L"Example: " << currentExePath << " unbind C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe" << std::endl;
}

#pragma comment(lib, "Bindlink.lib")
/*
* executes the shadowed exe, then points shadowed exe to backing exe with a bind link, see https://insomnihack.ch/talks/silo-binding-uncovering-the-ghost-in-the-silo/
*/
int wmain(int argc, wchar_t* argv[]) {
	wchar_t* currentExePath = argv[0];

    if (argc < 3) {
        std::wcout << L"Operation required" << std::endl;
        usage(currentExePath);
        return 1;
    }
	wchar_t* operation = argv[1];

    if (operation == nullptr || (wcscmp(operation, L"bind") != 0) && (wcscmp(operation, L"bind-exec") != 0) && (wcscmp(operation, L"unbind") != 0)) {
        std::wcout << L"Invalid operation: " << operation << std::endl;
        usage(currentExePath);
        return 1;
	}

    if (((wcscmp(operation, L"bind") == 0) || wcscmp(operation, L"bind-exec") == 0) && argc != 4) {
		std::wcout << L"Bind and bind-exec operations require backing and shadowed exe paths" << std::endl;
		usage(currentExePath);
        return 1;
    }

    if ((wcscmp(operation, L"unbind") == 0) && argc != 3) {
        std::wcout << L"Unbind operation requires shadowed exe path" << std::endl;
        usage(currentExePath);
        return 1;
    }

	// unbind operation
    if (wcscmp(operation, L"unbind") == 0) {
        wchar_t* shadowedExePath = argv[2];
        HRESULT hr = RemoveBindLink(shadowedExePath);
        if (FAILED(hr)) {
            std::wcerr << L"RemoveBindLink failed: 0x" << std::hex << hr << std::endl;
            return 1;
        }
        std::wcout << L"Success: " << shadowedExePath << " is now unbound" << std::endl;
        return 0;
	}

	// else bind operation
    wchar_t* backingExePath = argv[2];  // the backing path
    wchar_t* shadowedExePath = argv[3]; // redirected to backing exe (after initial execution)

    if (wcscmp(operation, L"bind-exec") == 0) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        if (!CreateProcessW(shadowedExePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            std::wcerr << L"Failed to execute " << shadowedExePath << L". Code: " << GetLastError() << std::endl;
            return 1;
        }
        std::wcout << L"Successfully executed the (to be) Shadowed Executable: " << shadowedExePath << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    HRESULT hr = CreateBindLink(
        shadowedExePath,  // Virtual Path (The Shadow)
        backingExePath,   // Backing Path (The Real Code)
        CREATE_BIND_LINK_FLAG_NONE,
        0, NULL
    );
    if (FAILED(hr)) {
        std::wcerr << L"CreateBindLink failed: 0x" << std::hex << hr << std::endl;
        return 1;
    }

    std::wcout << L"Success: " << shadowedExePath << L" now points to " << backingExePath << std::endl;

    return 0;
}
