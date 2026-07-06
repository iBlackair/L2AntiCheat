#define WIN32_LEAN_AND_MEAN
#include "NexoraDatHook.h"

#include "Hook.h"
#include "NexoraDatCrypt.h"

#include <windows.h>
#include <tlhelp32.h>
#include <cwchar>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

namespace
{
    typedef int(__cdecl* AppLoadFileToArrayFn)(void* result, const wchar_t* filename, void* fileManager);
    typedef HANDLE(WINAPI* CreateFileWFn)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef HANDLE(WINAPI* CreateFileAFn)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL(WINAPI* CloseHandleFn)(HANDLE);

    struct TempHandle
    {
        HANDLE handle;
        std::wstring path;
    };

    Hook::Trampoline g_LoadFileHook;
    AppLoadFileToArrayFn g_OriginalAppLoadFileToArray = NULL;
    CreateFileWFn g_OriginalCreateFileW = NULL;
    CreateFileAFn g_OriginalCreateFileA = NULL;
    CloseHandleFn g_OriginalCloseHandle = NULL;
    volatile LONG g_Installed = 0;
    volatile LONG g_TempCounter = 0;
    INIT_ONCE g_TempLockOnce = INIT_ONCE_STATIC_INIT;
    CRITICAL_SECTION g_TempLock;
    std::vector<TempHandle> g_TempHandles;
    __declspec(thread) int g_RedirectDepth = 0;

    BOOL CALLBACK InitTempLock(PINIT_ONCE, PVOID, PVOID*)
    {
        InitializeCriticalSection(&g_TempLock);
        return TRUE;
    }

    static void EnsureTempLock()
    {
        InitOnceExecuteOnce(&g_TempLockOnce, InitTempLock, NULL, NULL);
    }

    static void LogLine(const wchar_t* message)
    {
        wchar_t modulePath[MAX_PATH] = {};
        GetModuleFileNameW(NULL, modulePath, MAX_PATH);
        wchar_t* slash = wcsrchr(modulePath, L'\\');
        if (slash)
            slash[1] = L'\0';

        std::wstring logPath = modulePath;
        logPath += L"NexoraDatProtect.log";

        FILE* file = NULL;
        if (_wfopen_s(&file, logPath.c_str(), L"a, ccs=UTF-8") == 0 && file)
        {
            SYSTEMTIME st = {};
            GetLocalTime(&st);
            fwprintf(
                file,
                L"[%04u-%02u-%02u %02u:%02u:%02u] %s\n",
                st.wYear,
                st.wMonth,
                st.wDay,
                st.wHour,
                st.wMinute,
                st.wSecond,
                message ? message : L"");
            fclose(file);
        }
    }

    static bool EndsWithDat(const wchar_t* path)
    {
        if (!path)
            return false;

        const size_t len = wcslen(path);
        return len >= 4 && _wcsicmp(path + len - 4, L".dat") == 0;
    }

    static std::wstring FullPathFor(const wchar_t* path)
    {
        wchar_t full[MAX_PATH] = {};
        DWORD len = GetFullPathNameW(path, MAX_PATH, full, NULL);
        if (len > 0 && len < MAX_PATH)
            return full;
        return path ? path : L"";
    }

    static std::wstring MakeTempDatPath()
    {
        wchar_t tempDir[MAX_PATH] = {};
        DWORD len = GetTempPathW(MAX_PATH, tempDir);
        if (len == 0 || len >= MAX_PATH)
            wcscpy_s(tempDir, L".\\");

        wchar_t file[MAX_PATH] = {};
        swprintf_s(
            file,
            L"%sNexoraDat_%lu_%lu_%ld.dat",
            tempDir,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetTickCount()),
            InterlockedIncrement(&g_TempCounter));
        return file;
    }

    static void* ResolveRelativeJump(void* address)
    {
        unsigned char* bytes = static_cast<unsigned char*>(address);
        if (!bytes || bytes[0] != 0xE9)
            return address;

        const std::int32_t rel = *reinterpret_cast<std::int32_t*>(bytes + 1);
        return bytes + 5 + rel;
    }

    static bool IsReadOnlyOpen(DWORD desiredAccess, DWORD creationDisposition)
    {
        const DWORD writeAccess =
            GENERIC_WRITE |
            FILE_WRITE_DATA |
            FILE_APPEND_DATA |
            FILE_WRITE_ATTRIBUTES |
            FILE_WRITE_EA |
            WRITE_DAC |
            WRITE_OWNER;

        return (desiredAccess & writeAccess) == 0 &&
            (creationDisposition == OPEN_EXISTING || creationDisposition == OPEN_ALWAYS);
    }

    static bool BuildRedirectTempForDat(const wchar_t* filename, std::wstring& tempPath)
    {
        tempPath.clear();
        if (!filename || !EndsWithDat(filename))
            return false;

        const std::wstring fullPath = FullPathFor(filename);
        if (fullPath.empty())
            return false;

        ++g_RedirectDepth;
        const bool protectedFile = NexoraDatCrypt::IsProtectedFile(fullPath.c_str());
        --g_RedirectDepth;
        if (!protectedFile)
            return false;

        tempPath = MakeTempDatPath();
        std::wstring error;

        ++g_RedirectDepth;
        const bool unprotected = NexoraDatCrypt::UnprotectFile(fullPath.c_str(), tempPath.c_str(), error);
        --g_RedirectDepth;

        if (!unprotected)
        {
            std::wstring log = L"FileAPI falhou ao preparar Nexora DAT: ";
            log += fullPath;
            log += L" | ";
            log += error;
            LogLine(log.c_str());
            tempPath.clear();
            return false;
        }

        std::wstring log = L"FileAPI preparou Nexora DAT: ";
        log += fullPath;
        LogLine(log.c_str());
        return true;
    }

    static void TrackTempHandle(HANDLE handle, const std::wstring& tempPath)
    {
        if (!handle || handle == INVALID_HANDLE_VALUE || tempPath.empty())
            return;

        EnsureTempLock();
        EnterCriticalSection(&g_TempLock);
        TempHandle item = {};
        item.handle = handle;
        item.path = tempPath;
        g_TempHandles.push_back(item);
        LeaveCriticalSection(&g_TempLock);
    }

    static std::wstring TakeTempHandle(HANDLE handle)
    {
        std::wstring path;
        if (!handle || handle == INVALID_HANDLE_VALUE)
            return path;

        EnsureTempLock();
        EnterCriticalSection(&g_TempLock);
        for (std::vector<TempHandle>::iterator it = g_TempHandles.begin(); it != g_TempHandles.end(); ++it)
        {
            if (it->handle == handle)
            {
                path = it->path;
                g_TempHandles.erase(it);
                break;
            }
        }
        LeaveCriticalSection(&g_TempLock);
        return path;
    }

    static bool TryOpenRedirectedDat(
        const wchar_t* filename,
        DWORD desiredAccess,
        DWORD shareMode,
        LPSECURITY_ATTRIBUTES securityAttributes,
        DWORD creationDisposition,
        DWORD flagsAndAttributes,
        HANDLE templateFile,
        HANDLE& redirectedHandle)
    {
        redirectedHandle = INVALID_HANDLE_VALUE;
        if (!g_OriginalCreateFileW || g_RedirectDepth > 0 || !IsReadOnlyOpen(desiredAccess, creationDisposition))
            return false;

        std::wstring tempPath;
        if (!BuildRedirectTempForDat(filename, tempPath))
            return false;

        ++g_RedirectDepth;
        redirectedHandle = g_OriginalCreateFileW(
            tempPath.c_str(),
            desiredAccess,
            shareMode | FILE_SHARE_DELETE,
            securityAttributes,
            OPEN_EXISTING,
            flagsAndAttributes,
            templateFile);
        --g_RedirectDepth;

        if (redirectedHandle == INVALID_HANDLE_VALUE)
        {
            std::wstring log = L"FileAPI nao abriu temporario Nexora DAT: ";
            log += tempPath;
            LogLine(log.c_str());
            DeleteFileW(tempPath.c_str());
            return false;
        }

        TrackTempHandle(redirectedHandle, tempPath);
        std::wstring log = L"FileAPI entregou Nexora DAT ao cliente: ";
        log += tempPath;
        LogLine(log.c_str());
        return true;
    }

    HANDLE WINAPI HookedCreateFileW(
        LPCWSTR filename,
        DWORD desiredAccess,
        DWORD shareMode,
        LPSECURITY_ATTRIBUTES securityAttributes,
        DWORD creationDisposition,
        DWORD flagsAndAttributes,
        HANDLE templateFile)
    {
        HANDLE redirected = INVALID_HANDLE_VALUE;
        if (TryOpenRedirectedDat(
            filename,
            desiredAccess,
            shareMode,
            securityAttributes,
            creationDisposition,
            flagsAndAttributes,
            templateFile,
            redirected))
        {
            return redirected;
        }

        return g_OriginalCreateFileW
            ? g_OriginalCreateFileW(filename, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile)
            : INVALID_HANDLE_VALUE;
    }

    HANDLE WINAPI HookedCreateFileA(
        LPCSTR filename,
        DWORD desiredAccess,
        DWORD shareMode,
        LPSECURITY_ATTRIBUTES securityAttributes,
        DWORD creationDisposition,
        DWORD flagsAndAttributes,
        HANDLE templateFile)
    {
        if (filename && g_OriginalCreateFileW)
        {
            const int chars = MultiByteToWideChar(CP_ACP, 0, filename, -1, NULL, 0);
            if (chars > 0)
            {
                std::vector<wchar_t> wide(chars, L'\0');
                if (MultiByteToWideChar(CP_ACP, 0, filename, -1, &wide[0], chars) > 0)
                {
                    HANDLE redirected = INVALID_HANDLE_VALUE;
                    if (TryOpenRedirectedDat(
                        &wide[0],
                        desiredAccess,
                        shareMode,
                        securityAttributes,
                        creationDisposition,
                        flagsAndAttributes,
                        templateFile,
                        redirected))
                    {
                        return redirected;
                    }
                }
            }
        }

        return g_OriginalCreateFileA
            ? g_OriginalCreateFileA(filename, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile)
            : INVALID_HANDLE_VALUE;
    }

    BOOL WINAPI HookedCloseHandle(HANDLE handle)
    {
        const std::wstring tempPath = TakeTempHandle(handle);

        BOOL result = FALSE;
        if (g_OriginalCloseHandle)
            result = g_OriginalCloseHandle(handle);

        if (!tempPath.empty())
        {
            DeleteFileW(tempPath.c_str());
            std::wstring log = L"FileAPI removeu temporario Nexora DAT: ";
            log += tempPath;
            LogLine(log.c_str());
        }

        return result;
    }

    static bool PatchImportByName(HMODULE module, const char* importName, void* detour, void** original, int& patched)
    {
        if (!module || !importName || !detour)
            return false;

        unsigned char* base = reinterpret_cast<unsigned char*>(module);
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        const DWORD imageSize = nt->OptionalHeader.SizeOfImage;
        if (imageSize == 0)
            return false;

        IMAGE_DATA_DIRECTORY importDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!importDirectory.VirtualAddress)
            return false;

        const auto rvaOk = [imageSize](DWORD rva, DWORD bytes) -> bool
        {
            return rva != 0 && rva < imageSize && bytes <= imageSize - rva;
        };

        if (!rvaOk(importDirectory.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
            return false;

        IMAGE_IMPORT_DESCRIPTOR* descriptor =
            reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDirectory.VirtualAddress);

        bool any = false;
        for (int descriptorGuard = 0;
            descriptorGuard < 256 &&
            rvaOk(static_cast<DWORD>(reinterpret_cast<unsigned char*>(descriptor) - base), sizeof(IMAGE_IMPORT_DESCRIPTOR)) &&
            descriptor->Name;
            ++descriptorGuard, ++descriptor)
        {
            if (!rvaOk(descriptor->FirstThunk, sizeof(IMAGE_THUNK_DATA)))
                continue;

            if (descriptor->OriginalFirstThunk && !rvaOk(descriptor->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA)))
                continue;

            IMAGE_THUNK_DATA* originalThunk = descriptor->OriginalFirstThunk
                ? reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->OriginalFirstThunk)
                : reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->FirstThunk);
            IMAGE_THUNK_DATA* firstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->FirstThunk);

            for (int thunkGuard = 0; thunkGuard < 4096; ++thunkGuard, ++originalThunk, ++firstThunk)
            {
                const DWORD originalThunkRva = static_cast<DWORD>(reinterpret_cast<unsigned char*>(originalThunk) - base);
                const DWORD firstThunkRva = static_cast<DWORD>(reinterpret_cast<unsigned char*>(firstThunk) - base);
                if (!rvaOk(originalThunkRva, sizeof(IMAGE_THUNK_DATA)) || !rvaOk(firstThunkRva, sizeof(IMAGE_THUNK_DATA)))
                    break;

                if (!originalThunk->u1.AddressOfData)
                    break;

                if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
                    continue;

                const DWORD nameRva = static_cast<DWORD>(originalThunk->u1.AddressOfData);
                if (!rvaOk(nameRva, sizeof(IMAGE_IMPORT_BY_NAME)))
                    continue;

                IMAGE_IMPORT_BY_NAME* byName =
                    reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + nameRva);

                const char* currentName = reinterpret_cast<const char*>(byName->Name);
                const DWORD currentNameRva = static_cast<DWORD>(reinterpret_cast<const unsigned char*>(currentName) - base);
                if (!rvaOk(currentNameRva, 1))
                    continue;

                const DWORD maxNameBytes = imageSize - currentNameRva;
                bool sameName = false;
                for (DWORD i = 0; i < maxNameBytes; ++i)
                {
                    if (currentName[i] != importName[i])
                        break;
                    if (currentName[i] == '\0')
                    {
                        sameName = true;
                        break;
                    }
                }

                if (!sameName)
                    continue;

                void** slot = reinterpret_cast<void**>(&firstThunk->u1.Function);
                if (*slot == detour)
                    continue;

                if (original && !*original)
                    *original = *slot;

                DWORD oldProtect = 0;
                if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect))
                    continue;

                *slot = detour;

                DWORD tempProtect = 0;
                VirtualProtect(slot, sizeof(void*), oldProtect, &tempProtect);
                FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));

                ++patched;
                any = true;
            }
        }

        return any;
    }

    static std::wstring GetProcessDirectory()
    {
        wchar_t modulePath[MAX_PATH] = {};
        GetModuleFileNameW(NULL, modulePath, MAX_PATH);
        wchar_t* slash = wcsrchr(modulePath, L'\\');
        if (slash)
            slash[1] = L'\0';
        return modulePath;
    }

    static bool StartsWithPathNoCase(const wchar_t* path, const std::wstring& prefix)
    {
        if (!path || prefix.empty())
            return false;

        return _wcsnicmp(path, prefix.c_str(), prefix.size()) == 0;
    }

    static bool IsPatchableClientModule(const MODULEENTRY32W& entry, const std::wstring& processDirectory)
    {
        if (_wcsicmp(entry.szModule, L"dsetup.dll") == 0)
            return false;

        return StartsWithPathNoCase(entry.szExePath, processDirectory);
    }

    static int PatchFileApiImports()
    {
        std::vector<HMODULE> modules;
        const std::wstring processDirectory = GetProcessDirectory();
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        MODULEENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Module32FirstW(snapshot, &entry))
        {
            do
            {
                if (IsPatchableClientModule(entry, processDirectory))
                    modules.push_back(entry.hModule);
            } while (Module32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);

        int patched = 0;
        for (size_t i = 0; i < modules.size(); ++i)
        {
            PatchImportByName(modules[i], "CreateFileW", reinterpret_cast<void*>(&HookedCreateFileW), reinterpret_cast<void**>(&g_OriginalCreateFileW), patched);
            PatchImportByName(modules[i], "CreateFileA", reinterpret_cast<void*>(&HookedCreateFileA), reinterpret_cast<void**>(&g_OriginalCreateFileA), patched);
            PatchImportByName(modules[i], "CloseHandle", reinterpret_cast<void*>(&HookedCloseHandle), reinterpret_cast<void**>(&g_OriginalCloseHandle), patched);
        }

        return patched;
    }

    static void InstallFileApiHooks()
    {
        const int patched = PatchFileApiImports();
        if (patched > 0)
        {
            wchar_t message[128] = {};
            swprintf_s(message, L"Nexora DAT FileAPI hook atualizou %d import(s).", patched);
            LogLine(message);
        }
    }

    int __cdecl HookedAppLoadFileToArray(void* result, const wchar_t* filename, void* fileManager)
    {
        if (g_OriginalAppLoadFileToArray && filename && EndsWithDat(filename))
        {
            const std::wstring fullPath = FullPathFor(filename);
            if (!fullPath.empty() && NexoraDatCrypt::IsProtectedFile(fullPath.c_str()))
            {
                const std::wstring tempPath = MakeTempDatPath();
                std::wstring error;
                if (NexoraDatCrypt::UnprotectFile(fullPath.c_str(), tempPath.c_str(), error))
                {
                    std::wstring log = L"Nexora DAT entregue ao cliente: ";
                    log += fullPath;
                    LogLine(log.c_str());

                    const int resultCode = g_OriginalAppLoadFileToArray(result, tempPath.c_str(), fileManager);
                    DeleteFileW(tempPath.c_str());
                    return resultCode;
                }

                std::wstring log = L"Falha ao abrir Nexora DAT: ";
                log += fullPath;
                log += L" | ";
                log += error;
                LogLine(log.c_str());
            }
        }

        return g_OriginalAppLoadFileToArray
            ? g_OriginalAppLoadFileToArray(result, filename, fileManager)
            : 0;
    }

    DWORD WINAPI InstallThread(LPVOID)
    {
        InstallFileApiHooks();

        const char* exportName = "?appLoadFileToArray@@YAHAAV?$TArray@E@@PBGPAVFFileManager@@@Z";
        for (int attempt = 0; attempt < 300; ++attempt)
        {
            if ((attempt % 20) == 0)
                InstallFileApiHooks();

            HMODULE core = GetModuleHandleW(L"Core.dll");
            if (core)
            {
                FARPROC target = GetProcAddress(core, exportName);
                if (target)
                {
                    unsigned char* targetBytes = reinterpret_cast<unsigned char*>(target);
                    if (targetBytes[0] == 0xE9)
                    {
                        g_OriginalAppLoadFileToArray = reinterpret_cast<AppLoadFileToArrayFn>(ResolveRelativeJump(target));
                        if (Hook::WriteJump(reinterpret_cast<void*>(targetBytes), reinterpret_cast<void*>(&HookedAppLoadFileToArray)))
                        {
                            InstallFileApiHooks();
                            LogLine(L"Nexora DAT hook instalado no thunk de Core.dll!appLoadFileToArray.");
                            return 0;
                        }

                        LogLine(L"Nexora DAT hook falhou ao trocar thunk de Core.dll!appLoadFileToArray.");
                        g_OriginalAppLoadFileToArray = NULL;
                        return 1;
                    }

                    if (Hook::InstallHook(reinterpret_cast<void*>(target), reinterpret_cast<void*>(&HookedAppLoadFileToArray), 5, g_LoadFileHook))
                    {
                        g_OriginalAppLoadFileToArray = reinterpret_cast<AppLoadFileToArrayFn>(g_LoadFileHook.gateway);
                        InstallFileApiHooks();
                        LogLine(L"Nexora DAT hook instalado em Core.dll!appLoadFileToArray.");
                        return 0;
                    }

                    LogLine(L"Nexora DAT hook falhou ao instalar trampoline.");
                    return 1;
                }
            }
            Sleep(100);
        }

        LogLine(L"Nexora DAT hook nao encontrou Core.dll!appLoadFileToArray.");
        return 1;
    }
}

bool InitializeNexoraDatHook()
{
    if (InterlockedCompareExchange(&g_Installed, 1, 0) != 0)
        return true;

    HANDLE thread = CreateThread(NULL, 0, InstallThread, NULL, 0, NULL);
    if (!thread)
    {
        LogLine(L"Nexora DAT hook nao conseguiu criar thread.");
        return false;
    }
    CloseHandle(thread);
    return true;
}
