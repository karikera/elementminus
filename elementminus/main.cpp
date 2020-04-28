
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <iostream>

using namespace std;


void printErrorCode(DWORD err) noexcept
{
    LPWSTR buffer;
    if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr,
        err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buffer, 0, nullptr))
    {
        wcerr << buffer;
    }
    else
    {
        wcerr << L"0x" << hex << err << dec;
    }
    LocalFree(buffer);
}

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
) {
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        setlocale(LC_ALL, "");
        puts("Element Minus> Load mods\\*.dll");
        SetDllDirectoryW(L"mods");
        WIN32_FIND_DATA find;
        HANDLE handle = FindFirstFileW(L"mods\\*.dll", &find);
        if (handle != INVALID_HANDLE_VALUE)
        {
            wcout << L"Load " << find.cFileName << endl;
            do
            {
                if (!LoadLibraryW(find.cFileName))
                {
                    DWORD err = GetLastError();
                    wcerr << L"Load " << find.cFileName << L" failed: ";
                    printErrorCode(err);
                    wcerr << endl;
                }
            } while (FindNextFileW(handle, &find));
            FindClose(handle);
        }
        else
        {
            DWORD err = GetLastError();
            wcerr << L"Cannot read the mods directory: ";
            printErrorCode(err);
            wcerr << endl;
        }
    }
    return true;
}