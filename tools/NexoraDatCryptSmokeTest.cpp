#include <filesystem>
#include <iostream>
#include <string>

#include "../dsetup/NexoraDatCrypt.h"

namespace fs = std::filesystem;

int wmain(int argc, wchar_t** argv)
{
    if (argc != 3)
    {
        std::wcerr << L"usage: NexoraDatCryptSmokeTest <protected> <output>\n";
        return 2;
    }

    const fs::path protectedFile = argv[1];
    const fs::path outputFile = argv[2];
    std::wstring error;

    if (!NexoraDatCrypt::IsProtectedFile(protectedFile.c_str()))
    {
        std::wcerr << L"protected marker missing\n";
        return 3;
    }

    if (!NexoraDatCrypt::UnprotectFile(protectedFile.c_str(), outputFile.c_str(), error))
    {
        std::wcerr << L"unprotect failed: " << error << L"\n";
        return 4;
    }

    std::wcout << L"output=" << outputFile << L"\n";
    return 0;
}
