
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <unordered_set>

#include "resource.h"

using std::cout;
using std::cerr;
using std::endl;
using std::ostream;
using std::vector;
using std::unordered_set;
using std::wstring;

ostream& operator << (ostream& out, LPCWSTR wide) noexcept
{
    size_t wlen = lstrlenW(wide);
    if (wlen > INT_MAX) goto _invalid;

    {
        char buffer[1024];
        int len = WideCharToMultiByte(0, 0, wide, (int)wlen, buffer, (int)_countof(buffer), nullptr, nullptr);
        if (len != 0)
        {
            out.write(buffer, len);
            return out;
        }

        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto _invalid;

        vector<char> dynamicbuffer;
        size_t dstsize = 2048;
        dynamicbuffer.resize(dstsize);

        for (;;)
        {
            int len = WideCharToMultiByte(0, 0, wide, (int)wlen, dynamicbuffer.data(), (int)dstsize, nullptr, nullptr);
            if (len == 0)
            {
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto _invalid;
                if (dstsize >= INT_MAX) goto _invalid;
                dstsize *= 2;
                if (dstsize > INT_MAX) dstsize = INT_MAX;
                dynamicbuffer.resize(dstsize);
                continue;
            }
            dynamicbuffer.resize(len);
            break;
        }

        out.write(dynamicbuffer.data(), dynamicbuffer.size());
        return out;
    }

    _invalid:{
        out << "[Invalid String, len=" << wlen << ']';
        return out;
    }
}

void printErrorCode(DWORD err) noexcept
{
    cerr << "Error Code: " << err << endl;

    LPWSTR buffer;
    if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr,
        err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buffer, 0, nullptr))
    {

        cerr << "Error Message: " << buffer;
    }
    LocalFree(buffer);
}

class DllDumper
{
private:
    unordered_set<wstring> m_tested;

    bool checkFileInDirectory(LPWSTR dest, size_t dirname_len, LPCWSTR filename) noexcept
    {
        if (dirname_len >= MAX_PATH) return false;

        LPWSTR destfilename_ptr = dest + dirname_len;
        *destfilename_ptr++ = '\\';
        wcscpy_s(destfilename_ptr, (size_t)MAX_PATH - dirname_len - 1, filename);

        DWORD attr = GetFileAttributesW(dest);
        return attr != -1 && (attr & FILE_ATTRIBUTE_ARCHIVE) != 0;
    }

    WCHAR* getFilenameFromPath(WCHAR* filepath, DWORD len) noexcept
    {
        WCHAR* ptr = filepath + len;
        for (;;)
        {
            if (ptr == filepath) break;
            --ptr;
            if (*ptr == '\\')
            {
                ptr++;
                break;
            }
        }
        return ptr;
    }
    int stripFileNameOfPath(LPWSTR dest, DWORD len) noexcept
    {
        LPWSTR ptr = dest + len;
        for (;;)
        {
            if (ptr == dest) break;
            --ptr;
            if (*ptr == '\\')
            {
                *ptr = '\0';
                return (int)(ptr - dest);
            }
        }
        return 0;
    }
    
    bool FindDll(LPWSTR dest, LPCWSTR filename) noexcept
    {
        int len;
        len = GetModuleFileNameW(nullptr, dest, MAX_PATH);
        len = stripFileNameOfPath(dest, len);
        if (checkFileInDirectory(dest, len, filename)) return true;
        
        WCHAR dlldir[MAX_PATH];
        GetDllDirectoryW(MAX_PATH, dlldir);
        len = GetFullPathNameW(dlldir, MAX_PATH, dest, nullptr);
        if (checkFileInDirectory(dest, len, filename)) return true;

        // len = GetCurrentDirectoryW(MAX_PATH, dest);
        // if (writeFileNameToDir(dest, len, filename)) return true;

        len = GetSystemDirectoryW(dest, MAX_PATH);
        if (checkFileInDirectory(dest, len, filename)) return true;

        len = GetWindowsDirectoryW(dest, MAX_PATH);
        if (checkFileInDirectory(dest, len, filename)) return true;

        DWORD path_size = GetEnvironmentVariableW(L"PATH", nullptr, 0);
        vector<WCHAR> buffer(path_size);
        WCHAR* str = buffer.data();
        GetEnvironmentVariableW(L"PATH", str, path_size);
        wchar_t* ctx = str;
        for (;;) {
            wchar_t* dir = wcstok_s(ctx, L";", &ctx);
            if (dir == nullptr) break;
            size_t len = ctx - dir - (ctx[-1] == '\0');
            if (len >= MAX_PATH) continue;

            memcpy(dest, dir, len * sizeof(WCHAR));
            if (checkFileInDirectory(dest, len, filename)) return true;
        }
        return false;
    }

    PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, IMAGE_NT_HEADERS* pNTHeader) noexcept
    {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
        unsigned i;

        for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
        {
            // This 3 line idiocy is because Watcom's linker actually sets the
            // Misc.VirtualSize field to 0.  (!!! - Retards....!!!)
            DWORD size = section->Misc.VirtualSize;
            if (0 == size)
                size = section->SizeOfRawData;

            // Is the RVA within this section?
            if ((rva >= section->VirtualAddress) &&
                (rva < (section->VirtualAddress + size)))
                return section;
        }

        return 0;
    }
    LPVOID GetPtrFromRVA(DWORD rva, IMAGE_NT_HEADERS* pNTHeader, PBYTE imageBase) noexcept
    {
        PIMAGE_SECTION_HEADER pSectionHdr;
        INT delta;

        pSectionHdr = GetEnclosingSectionHeader(rva, pNTHeader);
        if (!pSectionHdr)
            return 0;

        delta = (INT)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
        return (PVOID)(imageBase + rva - delta);
    }

    WCHAR m_indent[256];
    WCHAR* m_pindent;
    
public:
    DllDumper() noexcept
    {
        m_indent[0] = L'¡¡';
        m_indent[1] = L'\0';
        m_pindent = m_indent;
    }

    bool FindNotFound(LPCWSTR filename) noexcept
    {
        if (wcsncmp(L"api-ms-win-", filename, 11) == 0) return false;

        auto res = m_tested.insert((wstring)filename);
        if (!res.second) return false;


        WCHAR dllpath[MAX_PATH];
        if (!FindDll(dllpath, filename))
        {
            if (*m_pindent == L'¦¢') *m_pindent = L'¦§';
            else *m_pindent = L'¦£';
            cerr << m_indent << ' ' << filename << ": not found" << endl;
            *m_pindent = L'¦¢';
            return true;
        }

        HANDLE file = CreateFileW(dllpath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        void* ptr = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);

        *++m_pindent = L'¡¡';
        m_pindent[1] = L'\0';

        bool dllPrinted = false;
        bool retValue = false;
        for (;;)
        {
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ptr;
            if (dos->e_magic != 'ZM') // MZ
            {
                cerr << m_indent << ' ' << filename << ": Invalid DLL, DOS signature does not match" << endl;
                retValue = true;
                break;
            }

            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)dos + dos->e_lfanew);
            if (nt->Signature != 'EP') // PE\0\0
            {
                cerr << m_indent << ' ' << filename << ": Invalid DLL, NT signature does not match" << endl;
                retValue = true;
                break;
            }

            PBYTE imageBase = (PBYTE)ptr;

            if (nt->OptionalHeader.NumberOfRvaAndSizes < 2) break;
            
            DWORD importdesc_vaddr = nt->OptionalHeader.DataDirectory[1].VirtualAddress;
            if (importdesc_vaddr == 0) break;

            PIMAGE_IMPORT_DESCRIPTOR importDesc =
                (PIMAGE_IMPORT_DESCRIPTOR)GetPtrFromRVA(
                    importdesc_vaddr,
                    nt, imageBase);
            for (;;)
            {
                // See if we've reached an empty IMAGE_IMPORT_DESCRIPTOR
                if ((importDesc->TimeDateStamp == 0) && (importDesc->Name == 0))
                    break;

                LPCSTR name = (LPCSTR)GetPtrFromRVA(importDesc->Name,
                    nt,
                    imageBase);

                WCHAR name_w[MAX_PATH];
                int name_w_len = MultiByteToWideChar(CP_ACP, 0, name, (int)strlen(name), name_w, MAX_PATH);
                name_w[name_w_len] = '\0';
                if (FindNotFound(name_w))
                {
                    retValue = true;
                }
                importDesc++;
            }

            break;
        }
        *m_pindent = '\0';
        m_pindent--;

        if (retValue)
        {
            cerr << m_indent << ' ' << filename << endl;
        }

        UnmapViewOfFile(ptr);
        CloseHandle(mapping);
        CloseHandle(file);
        return retValue;
    }

};

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
) {
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        SetDllDirectoryW(L"redstone");
        WIN32_FIND_DATA find;
        HANDLE handle = FindFirstFileW(L"redstone\\*.dll", &find);
        if (handle != INVALID_HANDLE_VALUE)
        {
            DllDumper dlldumper;
            do
            {
                HMODULE already = GetModuleHandleW(find.cFileName);
                if (already == nullptr)
                {
                    if (!LoadLibraryW(find.cFileName))
                    {
                        DWORD err = GetLastError();
                        cout << "[EMinus] redstone\\" << find.cFileName << ": Failed" << endl;
                        printErrorCode(err);
                        if (err == ERROR_MOD_NOT_FOUND)
                        {
                            dlldumper.FindNotFound(find.cFileName);
                        }
                        cerr << endl;
                    }
                }
            } while (FindNextFileW(handle, &find));
            FindClose(handle);
        }
        else
        {
            DWORD err = GetLastError();
            cerr << "[EMinus] Cannot read the redstone directory: ";
            printErrorCode(err);
            cerr << endl;
        }
    }
    return true;
}